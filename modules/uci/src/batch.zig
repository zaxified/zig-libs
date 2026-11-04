// SPDX-License-Identifier: MIT

//! `uci batch` and `uci import -m` over `Store`: a `Session` holds one
//! `Editor` per package (loaded with its staged delta), runs command scripts
//! on them and commits. Nothing reaches the disk before `commit`; a failed
//! command leaves the commands before it applied IN MEMORY, and `discard`
//! drops the lot.
//!
//! Behaviour measured on the real binary (`tools/capture-store.sh`): commands
//! `set add add_list del_list delete rename reorder revert commit`, one per
//! line, words split like the file grammar; `batch` itself goes on after a
//! failing line and exits 0 (`RunOptions.keep_going` reproduces that; the
//! default stops at the first failure, which is the safer reading and the
//! deliberate difference). Not done: `get`/`show`/`export` (read the `Editor`
//! directly), `revert pkg.sec[.opt]` (`UnsupportedCommand`), `delete pkg`.

const std = @import("std");
const root = @import("root.zig");
const edit = @import("edit.zig");
const store_mod = @import("store.zig");
const diff = @import("diff.zig");
const Allocator = std.mem.Allocator;
const Editor = edit.Editor;
const Package = root.Package;
const Store = store_mod.Store;

pub const SessionError = store_mod.StagedError || store_mod.CommitError || error{
    /// The command word is not one `batch` knows.
    UnknownCommand,
    /// Wrong number of arguments, no `=`, a bad number, or a package-only reference.
    BadCommand,
    /// A command the session does not do (`revert` below package level).
    UnsupportedCommand,
    /// More than `max_packages` packages open in one session.
    TooManyPackages,
};

pub const max_packages: usize = 256;

/// All open packages of one session together: sections + options + values.
/// One package alone may hold `root.max_total_items`; the session twice that.
pub const max_session_items: usize = 2 * root.max_total_items;

pub const RunOptions = struct {
    /// Go on after a failing command (what `uci batch` does). The failures
    /// are counted in `RunReport`. Default: stop at the first one.
    keep_going: bool = false,
};

pub const RunReport = struct {
    /// Commands that succeeded.
    executed: usize = 0,
    /// Commands that failed (more than one only with `keep_going`).
    failed: usize = 0,
    /// 0-based index of the first failing command; meaningful when `failed > 0`.
    first_failed: usize = 0,
    /// Its error.
    first_error: ?SessionError = null,
};

const Entry = struct {
    name: []u8,
    ed: Editor,
    /// The config file as it was before the editor was loaded.
    stamp: ?store_mod.Stamp,
    dirty: bool = false,
};

pub const Session = struct {
    gpa: Allocator,
    store: Store,
    entries: std.ArrayList(Entry) = .empty,
    /// Editor work spent by the current `run` (see `edit.max_delta_work`).
    spent: u64 = 0,

    pub fn init(gpa: Allocator, store: Store) Session {
        return .{ .gpa = gpa, .store = store };
    }

    pub fn deinit(self: *Session) void {
        for (self.entries.items) |*e| {
            e.ed.deinit();
            self.gpa.free(e.name);
        }
        self.entries.deinit(self.gpa);
        self.* = undefined;
    }

    fn indexOf(self: *const Session, name: []const u8) ?usize {
        for (self.entries.items, 0..) |e, i| if (std.mem.eql(u8, e.name, name)) return i;
        return null;
    }

    /// The editor of package `name`, loaded (committed file + staged delta) on
    /// first use. The pointer is valid until the next `editor`/`run` call that
    /// opens another package, or `discard`/`deinit`.
    pub fn editor(self: *Session, name: []const u8) SessionError!*Editor {
        if (self.indexOf(name)) |i| return &self.entries.items[i].ed;
        if (self.entries.items.len >= max_packages) return error.TooManyPackages;
        const owned = try self.gpa.dupe(u8, name);
        errdefer self.gpa.free(owned);
        const stamp = try self.store.stamp(name);
        var ed = try self.freshEditor(name);
        errdefer ed.deinit();
        var total: usize = ed.items;
        for (self.entries.items) |e| total +|= e.ed.items;
        if (total > max_session_items) return error.MemoryLimitExceeded;
        try self.entries.append(self.gpa, .{ .name = owned, .ed = ed, .stamp = stamp });
        return &self.entries.items[self.entries.items.len - 1].ed;
    }

    /// The committed file, the `extra_save` deltas and `save`'s delta, replayed
    /// on one editor so its anonymous ids are the ones the delta records use.
    fn freshEditor(self: *Session, name: []const u8) SessionError!Editor {
        var ed = try self.store.baseEditor(self.gpa, name, null);
        errdefer ed.deinit();
        if (try self.store.staged(self.gpa, name)) |bytes| {
            defer self.gpa.free(bytes);
            try ed.applyDelta(name, bytes, null);
        }
        return ed;
    }

    /// Re-read entry `i` from disk (after a commit its editor must agree with
    /// the file). The slot, and so the `*Editor` pointer, stays the same.
    fn reload(self: *Session, i: usize) SessionError!void {
        const stamp = try self.store.stamp(self.entries.items[i].name);
        const fresh = try self.freshEditor(self.entries.items[i].name);
        self.entries.items[i].ed.deinit();
        self.entries.items[i].ed = fresh;
        self.entries.items[i].stamp = stamp;
        self.entries.items[i].dirty = false;
    }

    /// `save`: write the session's staged changes of `name` as the package's
    /// delta file (needs `Store.save`), for another process to see.
    pub fn save(self: *Session, name: []const u8) SessionError!void {
        const ed = try self.editor(name);
        try self.store.saveEditor(self.gpa, name, ed);
    }

    /// Start a new editor work budget (the budget is per session, not per run).
    pub fn resetBudget(self: *Session) void {
        self.spent = 0;
    }

    /// Drop the in-memory state of `name` (an unwritten edit is lost).
    pub fn discard(self: *Session, name: []const u8) void {
        const i = self.indexOf(name) orelse return;
        var e = self.entries.orderedRemove(i);
        e.ed.deinit();
        self.gpa.free(e.name);
    }

    fn markDirty(self: *Session, name: []const u8) void {
        if (self.indexOf(name)) |i| self.entries.items[i].dirty = true;
    }

    /// `uci commit [<pkg>]`: BEFORE the write, each package's file is compared
    /// with the `Stamp` taken when its editor was loaded: another process's
    /// commit in between is `ChangedOnDisk` and nothing is written (discard the
    /// package and redo the edits, or `Store.replace` to overwrite on purpose).
    /// After `CommittedNotDurable` / `StagedNotCleared` the new file IS on disk
    /// but the editor is left as it was: stale, still dirty, its stamp old, so a
    /// retry gives `ChangedOnDisk`. The next step is `discard` (the next
    /// `editor` call reloads from disk). Writes `name` (or, with null, every package this
    /// session changed) and empty the deltas. A package the session never
    /// opened is committed from its staged delta. Packages are written one
    /// after the other: a failure in the middle leaves the earlier ones
    /// committed (each of them atomically).
    pub fn commit(self: *Session, name: ?[]const u8) SessionError!void {
        if (name) |n| {
            if (self.indexOf(n)) |i| {
                try self.store.commitEditor(self.gpa, n, &self.entries.items[i].ed, self.entries.items[i].stamp);
                try self.reload(i);
            } else try self.store.commitStaged(self.gpa, n, null);
            return;
        }
        for (self.entries.items, 0..) |*e, i| {
            if (!e.dirty) continue;
            try self.store.commitEditor(self.gpa, e.name, &e.ed, e.stamp);
            try self.reload(i);
        }
    }

    /// Run a `uci batch` script. See the module comment for the command set.
    pub fn run(self: *Session, script_text: []const u8, opts: RunOptions, report: ?*RunReport, diag: ?*root.Diagnostics) SessionError!void {
        var script = try root.parseScript(self.gpa, script_text, diag);
        defer script.deinit(self.gpa);
        var rep: RunReport = .{};
        defer if (report) |r| {
            r.* = rep;
        };
        for (script.commands, 0..) |words, idx| {
            self.runOne(words) catch |e| {
                // Memory and a crash are never "a failing line".
                if (e == error.OutOfMemory or e == error.WorkLimitExceeded) return e;
                if (rep.failed == 0) {
                    rep.first_failed = idx;
                    rep.first_error = e;
                }
                rep.failed += 1;
                if (!opts.keep_going) return e;
                continue;
            };
            rep.executed += 1;
            // A hostile script of cheap-looking commands must not run for ever:
            // the editors count what their lookups and moves cost.
            if (self.spent > edit.max_delta_work) return error.WorkLimitExceeded;
        }
    }

    fn runOne(self: *Session, words: []const []const u8) SessionError!void {
        const cmd = words[0];
        const eq = std.StaticStringMap(Cmd).initComptime(.{
            .{ "set", .set },       .{ "add", .add },       .{ "add_list", .add_list }, .{ "del_list", .del_list },
            .{ "delete", .delete }, .{ "rename", .rename }, .{ "reorder", .reorder },   .{ "revert", .revert },
            .{ "commit", .commit },
        });
        const c = eq.get(cmd) orelse return error.UnknownCommand;
        switch (c) {
            .add => {
                if (words.len != 3) return error.BadCommand;
                const ed = try self.editor(words[1]);
                _ = try ed.add(words[2]);
                self.markDirty(words[1]);
            },
            .commit => {
                if (words.len > 2) return error.BadCommand;
                try self.commit(if (words.len == 2) words[1] else null);
            },
            .revert => {
                if (words.len != 2) return error.BadCommand;
                const a = try splitRef(words[1], false);
                const sec = a.sec orelse {
                    self.discard(a.pkg);
                    return self.store.revert(a.pkg);
                };
                // below package level: put the section (or option) back to what
                // the committed file says, through the records that would do it
                const ed = try self.editor(a.pkg);
                var bed = try self.store.baseEditor(self.gpa, a.pkg, null);
                defer bed.deinit();
                const id: []const u8 = if (ed.find(sec)) |i| ed.sections.items[i].id else if (sec[0] == '@') return error.NoSuchSection else sec;
                const recs = try diff.diffRecords(self.gpa, ed, &bed, a.pkg, .{ .section = id, .key = a.key });
                defer self.gpa.free(recs);
                try ed.applyDelta(a.pkg, recs, null);
                self.markDirty(a.pkg);
            },
            else => {
                if (words.len != 2) return error.BadCommand;
                try self.runRef(c, words[1]);
            },
        }
    }

    const Cmd = enum { set, add, add_list, del_list, delete, rename, reorder, revert, commit };

    fn runRef(self: *Session, c: Cmd, arg: []const u8) SessionError!void {
        const a = try splitRef(arg, c != .delete);
        const sec = a.sec orelse return error.BadCommand;
        const ed = try self.editor(a.pkg);
        const w0 = ed.work;
        defer self.spent +|= ed.work -| w0;
        if (self.spent > edit.max_delta_work) return error.WorkLimitExceeded;
        switch (c) {
            .set => {
                const v = a.value orelse return error.BadCommand;
                if (a.key) |k| try ed.set(sec, k, v) else try ed.setSection(sec, v);
            },
            .add_list => {
                const v = a.value orelse return error.BadCommand;
                try ed.addList(sec, a.key orelse return error.BadCommand, v);
            },
            .del_list => {
                const v = a.value orelse return error.BadCommand;
                try ed.delList(sec, a.key orelse return error.BadCommand, v);
            },
            .delete => {
                if (a.key) |k| {
                    if (a.value) |v| {
                        const n = std.fmt.parseInt(usize, v, 10) catch return error.BadCommand;
                        try ed.deleteListItem(sec, k, n);
                    } else try ed.deleteOption(sec, k);
                } else {
                    if (a.value != null) return error.BadCommand;
                    try ed.delete(sec);
                }
            },
            .rename => {
                const v = a.value orelse return error.BadCommand;
                if (a.key) |k| try ed.renameOption(sec, k, v) else try ed.rename(sec, v);
            },
            .reorder => {
                const v = a.value orelse return error.BadCommand;
                if (a.key != null) return error.BadCommand;
                try ed.reorder(sec, std.fmt.parseInt(usize, v, 10) catch return error.BadCommand);
            },
            else => unreachable,
        }
        self.markDirty(a.pkg);
    }
};

const Ref = struct {
    pkg: []const u8,
    sec: ?[]const u8 = null,
    key: ?[]const u8 = null,
    value: ?[]const u8 = null,
};

/// `pkg[.sec[.key]][=value]`. The value starts at the FIRST `=` (it may hold
/// more); `@type[N]` has no dot, so splitting on dots is safe.
fn splitRef(arg: []const u8, want_value: bool) SessionError!Ref {
    var left = arg;
    var value: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, arg, '=')) |eq| {
        left = arg[0..eq];
        value = arg[eq + 1 ..];
    } else if (want_value) return error.BadCommand;
    var r: Ref = .{ .pkg = left, .value = value };
    if (std.mem.indexOfScalar(u8, left, '.')) |d1| {
        r.pkg = left[0..d1];
        const rest = left[d1 + 1 ..];
        if (std.mem.indexOfScalar(u8, rest, '.')) |d2| {
            r.sec = rest[0..d2];
            r.key = rest[d2 + 1 ..];
        } else r.sec = rest;
    }
    if (r.pkg.len == 0) return error.BadCommand;
    if (r.sec) |s| if (s.len == 0) return error.BadCommand;
    if (r.key) |k| if (k.len == 0) return error.BadCommand;
    return r;
}

/// `uci import -m`: merge `pkg` into `ed`. Measured: a named section of the
/// text is created or, if it exists, must have the same type (else
/// `DuplicateSection`: the binary refuses that as a parse error); an
/// anonymous section is always ADDED; an `option` sets, a `list` entry is
/// appended (turning a single option into a list); options the text lacks stay.
///
/// Atomic against everything but allocation failure: the whole text is checked
/// first (names, types, keys, a type clash, the item cap) and nothing changes
/// when that fails; an `OutOfMemory` in the second pass can leave the editor
/// partly merged (discard it).
pub fn merge(ed: *Editor, pkg: *const Package) edit.EditError!void {
    var add_items: usize = 0;
    for (pkg.sections) |*s| {
        if (s.type.len == 0 or !root.validTypeChars(s.type)) return error.InvalidName;
        add_items +|= 1;
        if (s.name) |n| {
            if (n.len == 0 or !root.validNameChars(n)) return error.InvalidName;
            if (ed.find(n)) |i| {
                if (!std.mem.eql(u8, ed.sections.items[i].type, s.type)) return error.DuplicateSection;
            }
        }
        for (s.options) |*o| {
            if (o.key.len == 0 or !root.validNameChars(o.key)) return error.InvalidName;
            add_items +|= 1 + o.values.len;
        }
    }
    if (add_items > root.max_total_items -| ed.items) return error.MemoryLimitExceeded;
    for (pkg.sections) |*s| {
        var ref: []const u8 = undefined;
        if (s.name) |n| {
            if (ed.find(n)) |i| {
                if (!std.mem.eql(u8, ed.sections.items[i].type, s.type)) return error.DuplicateSection;
            } else try ed.setSection(n, s.type);
            ref = n;
        } else ref = try ed.add(s.type);
        for (s.options) |*o| {
            switch (o.kind) {
                .single => for (o.values) |v| try ed.set(ref, o.key, v),
                .list => for (o.values) |v| try ed.addList(ref, o.key, v),
            }
        }
    }
}
