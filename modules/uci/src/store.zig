// SPDX-License-Identifier: MIT

//! The file layer of `uci`: load a package from a config directory, overlay
//! its staged delta, and write it back with `commit` -- a temp file in the same
//! directory, `fsync`, `rename(2)` over the old file, `fsync` of the directory
//! (so a crash leaves the old file or the new one, never a mixture, and a
//! `commit` that returned is on stable media).
//!
//! Clean-room: behaviour from running the real `uci` binary as a black box
//! (`tools/capture-store.sh`); no libuci source was read. Measured and kept:
//! a commit replaces the file (new inode) and keeps its mode; a file created by
//! `import` is `0600`; a committed file has no `package` line; after a commit
//! or `revert` the delta file stays, empty; `import` (without `-m`) writes the
//! package at once and leaves the delta alone; a FIFO or `/dev/zero` named as a
//! package reads as "not found" in the binary. Deliberate differences, all on
//! the safe side: a package name with a `/` or `..` is refused (the binary
//! refuses it too, as a parse error), a symlink is refused rather than
//! followed, and a file `parse` could not read back is never written.
//!
//! What this does NOT prove: that a commit survives a power loss on a medium
//! or filesystem that lies about `fsync`; that two writers (this and a `uci`
//! process) do not overwrite each other (no lock is taken, the last
//! `rename` wins, as with two `uci commit` runs without the binary's own
//! file lock); that ownership is preserved (the mode is).

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const edit = @import("edit.zig");
const Allocator = std.mem.Allocator;
const Package = root.Package;

pub const StoreError = error{
    /// The package name is empty, too long or has a character outside
    /// `A-Za-z0-9_-` (with `Options.allow_paths`: empty, over 255 bytes, or a NUL).
    InvalidPackageName,
    /// The file is absent. Only this -- EMFILE, EIO, EACCES and the rest are
    /// `ReadFailed`/`AccessDenied`, never "absent".
    PackageNotFound,
    /// The name is a directory, FIFO, device or symlink. Nothing was read.
    NotRegularFile,
    /// The file is over `Options.max_bytes`, or `serialize` produced more than
    /// that. Nothing was read in full or written.
    FileTooLarge,
    AccessDenied,
    ReadFailed,
    WriteFailed,
    /// The new text would not read back as the same package (a line over
    /// `max_line_len`, text over `max_input_len`, or a model `parse` reads
    /// differently). Nothing was written.
    WouldNotReload,
    /// The new file is in place and durable, but emptying the package's delta
    /// failed: call `revert` again before trusting `loadStaged`.
    StagedNotCleared,
    OutOfMemory,
};

pub const Options = struct {
    /// Let a package name be a relative path (`sub/dir/net`, even with `..`)
    /// or absolute. Off by default: a name that comes from a request or a
    /// message must not leave the config directory.
    allow_paths: bool = false,
    /// Largest file read or written, in bytes.
    max_bytes: usize = root.max_input_len,
};

pub const LoadError = StoreError || root.ParseError;
pub const StagedError = LoadError || edit.DeltaError;
pub const CommitError = StoreError || root.SerializeError || edit.EditError || CrashError;

/// Only a test build can be told to stop in the middle of a commit.
const CrashError = if (builtin.is_test) error{SimulatedCrash} else error{};

pub const max_name_len: usize = 128;

/// True for a name that is one plain file name in the config directory:
/// 1..128 bytes of `A-Za-z0-9_-` (the binary also refuses `.`, `/` and
/// spaces, measured).
pub fn validPackageName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;
    for (name) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-')) return false;
    }
    return true;
}

const Class = enum { absent, denied, other };

/// Error classes by name, so one function serves every std error set.
fn classify(e: anyerror) Class {
    const n = @errorName(e);
    if (std.mem.eql(u8, n, "FileNotFound") or std.mem.eql(u8, n, "NotDir")) return .absent;
    if (std.mem.eql(u8, n, "AccessDenied") or std.mem.eql(u8, n, "PermissionDenied") or std.mem.eql(u8, n, "ReadOnlyFileSystem")) return .denied;
    return .other;
}

var temp_counter: std.atomic.Value(usize) = .init(0); // usize: mips32 has no 64-bit atomics

pub const Store = struct {
    io: std.Io,
    /// The config directory (`/etc/config`).
    conf: std.Io.Dir,
    /// The save directory with the staged deltas (`/tmp/.uci`); null = no
    /// staging: nothing is overlaid and `commit` has nothing to clear.
    save: ?std.Io.Dir = null,
    options: Options = .{},

    fn checkName(self: Store, name: []const u8) StoreError!void {
        if (self.options.allow_paths) {
            if (name.len == 0 or name.len > 255 or std.mem.indexOfScalar(u8, name, 0) != null) return error.InvalidPackageName;
        } else if (!validPackageName(name)) return error.InvalidPackageName;
    }

    /// The bytes of a regular file `name` in `dir`: null if it is absent,
    /// `NotRegularFile` for anything else that exists (a FIFO would block
    /// `open` and `/dev/zero` never ends; a symlink is not followed), and an
    /// error for every failure to look or read. The path is `lstat`ed first
    /// and the opened handle checked again; a FIFO swapped in inside that
    /// window still blocks `open` (`OpenFileOptions` has no non-blocking flag),
    /// as in `blobstore`.
    fn readRegular(self: Store, gpa: Allocator, dir: std.Io.Dir, name: []const u8) StoreError!?[]u8 {
        const io = self.io;
        const st = dir.statFile(io, name, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => return null,
            .denied => return error.AccessDenied,
            .other => return error.ReadFailed,
        };
        if (st.kind != .file) return error.NotRegularFile;
        const f = dir.openFile(io, name, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => return null,
            .denied => return error.AccessDenied,
            .other => return error.ReadFailed,
        };
        defer f.close(io);
        const st2 = f.stat(io) catch return error.ReadFailed;
        if (st2.kind != .file) return error.NotRegularFile;
        if (st2.size > self.options.max_bytes) return error.FileTooLarge;
        const size: usize = @intCast(st2.size);
        const buf = try gpa.alloc(u8, size);
        errdefer gpa.free(buf);
        const n = f.readPositionalAll(io, buf, 0) catch return error.ReadFailed;
        if (n != size) return error.ReadFailed; // shrank under us
        var extra: [1]u8 = undefined;
        const m = f.readPositionalAll(io, &extra, size) catch return error.ReadFailed;
        if (m != 0) return error.ReadFailed; // grew under us: not a consistent read
        return buf;
    }

    /// `uci -f <file>`: the bytes of the regular file `name` in `dir` (an
    /// import or batch script the caller then hands to `importText` or
    /// `Session.run`). Same name rule and same refusals as a package:
    /// `InvalidPackageName` for a path or `..` unless `Options.allow_paths`,
    /// `NotRegularFile` for a FIFO/device/symlink/directory, `FileTooLarge`
    /// past `Options.max_bytes`, `PackageNotFound` when absent. Caller frees.
    pub fn readFile(self: Store, gpa: Allocator, dir: std.Io.Dir, name: []const u8) StoreError![]u8 {
        try self.checkName(name);
        return (try self.readRegular(gpa, dir, name)) orelse error.PackageNotFound;
    }

    /// The committed file of `name`, parsed. `PackageNotFound` if there is none.
    pub fn load(self: Store, gpa: Allocator, name: []const u8, diag: ?*root.Diagnostics) LoadError!Package {
        try self.checkName(name);
        const bytes = (try self.readRegular(gpa, self.conf, name)) orelse return error.PackageNotFound;
        defer gpa.free(bytes);
        return root.parseDiag(gpa, bytes, diag);
    }

    /// The raw delta file of `name` (what `uci changes` is made from); null
    /// when there is no save directory or no file. An EMPTY slice is a delta
    /// that was reverted or committed: nothing is pending.
    pub fn staged(self: Store, gpa: Allocator, name: []const u8) StoreError!?[]u8 {
        try self.checkName(name);
        const save = self.save orelse return null;
        return self.readRegular(gpa, save, name);
    }

    /// True when `name` has staged changes: the delta's CONTENT, not the
    /// file's existence (an emptied delta stays on disk).
    pub fn hasStaged(self: Store, gpa: Allocator, name: []const u8) StoreError!bool {
        const d = (try self.staged(gpa, name)) orelse return false;
        defer gpa.free(d);
        return d.len != 0;
    }

    /// What `uci get`/`uci show` report: the committed file with the staged
    /// delta replayed on it.
    pub fn loadStaged(self: Store, gpa: Allocator, name: []const u8, diag: ?*root.Diagnostics) StagedError!Package {
        var base = try self.load(gpa, name, diag);
        errdefer base.deinit(gpa);
        const delta = (try self.staged(gpa, name)) orelse return base;
        defer gpa.free(delta);
        if (delta.len == 0) return base;
        const live = try edit.applyDelta(gpa, &base, name, delta, diag);
        base.deinit(gpa);
        return live;
    }

    /// `uci revert <pkg>`: discard the staged changes of the package by
    /// emptying its delta file (the binary leaves it there, empty; measured).
    /// No delta file, or no save directory: nothing to do.
    pub fn revert(self: Store, name: []const u8) StoreError!void {
        try self.checkName(name);
        const save = self.save orelse return;
        const st = save.statFile(self.io, name, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => return,
            .denied => return error.AccessDenied,
            .other => return error.WriteFailed,
        };
        if (st.kind != .file) return error.NotRegularFile;
        const f = save.createFile(self.io, name, .{ .truncate = true }) catch |e| switch (classify(e)) {
            .denied => return error.AccessDenied,
            else => return error.WriteFailed,
        };
        f.close(self.io);
    }

    /// `uci commit <pkg>` from a model: write `pkg` as the package's file
    /// (atomically, durably; see the module comment), then empty its delta.
    /// `pkg.name` is not written (a committed file has no `package` line).
    pub fn commit(self: Store, gpa: Allocator, name: []const u8, pkg: *const Package) CommitError!void {
        try self.replace(gpa, name, pkg);
        self.revert(name) catch return error.StagedNotCleared;
    }

    /// `commit` of an `Editor`'s current state.
    pub fn commitEditor(self: Store, gpa: Allocator, name: []const u8, ed: *const edit.Editor) CommitError!void {
        var pkg = try ed.toPackage(gpa);
        defer pkg.deinit(gpa);
        try self.commit(gpa, name, &pkg);
    }

    /// `uci commit <pkg>` for a package edited by other processes: replay the
    /// delta on the committed file and write the result. No pending delta:
    /// nothing is written (the binary also returns success).
    pub fn commitStaged(self: Store, gpa: Allocator, name: []const u8, diag: ?*root.Diagnostics) (StagedError || CommitError)!void {
        if (!try self.hasStaged(gpa, name)) {
            // Still `PackageNotFound` for a package that does not exist.
            var p = try self.load(gpa, name, diag);
            p.deinit(gpa);
            return;
        }
        var live = try self.loadStaged(gpa, name, diag);
        defer live.deinit(gpa);
        try self.commit(gpa, name, &live);
    }

    /// `uci import <pkg>` (no `-m`): parse `text` and make it the package's
    /// file at once. The delta is left alone, as the binary does (measured): a
    /// record for a section the new text lacks changes nothing, an `add`
    /// record would add again. A text that does not parse writes nothing. For
    /// `-m`, `merge` into an `Editor` and `commitEditor`.
    pub fn importText(self: Store, gpa: Allocator, name: []const u8, text: []const u8, diag: ?*root.Diagnostics) (root.ParseError || CommitError)!void {
        try self.checkName(name);
        var pkg = try root.parseDiag(gpa, text, diag);
        defer pkg.deinit(gpa);
        try self.replace(gpa, name, &pkg);
    }

    /// Write `pkg` as the file of `name` (no delta handling): the atomic part.
    pub fn replace(self: Store, gpa: Allocator, name: []const u8, pkg: *const Package) CommitError!void {
        try self.checkName(name);
        var view = pkg.*;
        view.name = null;
        const text = try root.serialize(gpa, &view);
        defer gpa.free(text);
        try checkReloads(gpa, text, &view, self.options.max_bytes);

        // Keep the mode of the file being replaced; a new file is 0600 (what
        // `uci import` creates, measured).
        const st = self.conf.statFile(self.io, name, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => null,
            .denied => return error.AccessDenied,
            .other => return error.WriteFailed,
        };
        var perms: std.Io.File.Permissions = @fromBackingInt(@intCast(0o600));
        if (st) |s| {
            if (s.kind != .file) return error.NotRegularFile;
            perms = s.permissions;
        }

        var tbuf: [512]u8 = undefined;
        const dir_part = std.fs.path.dirname(name);
        const base = std.fs.path.basename(name);
        var tmp: []const u8 = undefined;
        var file: std.Io.File = undefined;
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            if (attempt == 32) return error.WriteFailed;
            const n = temp_counter.fetchAdd(1, .monotonic);
            tmp = std.fmt.bufPrint(&tbuf, "{s}{s}.{s}.uci-tmp-{d}-{d}", .{
                dir_part orelse "",
                if (dir_part != null) "/" else "",
                base,
                std.os.linux.getpid(),
                n,
            }) catch return error.InvalidPackageName;
            file = self.conf.createFile(self.io, tmp, .{ .exclusive = true, .permissions = @fromBackingInt(@intCast(0o600)) }) catch |e| {
                if (std.mem.eql(u8, @errorName(e), "PathAlreadyExists")) continue;
                return switch (classify(e)) {
                    .denied => error.AccessDenied,
                    else => error.WriteFailed,
                };
            };
            break;
        }
        var renamed = false;
        defer if (!renamed and !(builtin.is_test and crash_hook.at != null)) self.conf.deleteFile(self.io, tmp) catch {};
        {
            defer file.close(self.io);
            file.writeStreamingAll(self.io, text) catch return error.WriteFailed;
            file.setPermissions(self.io, perms) catch return error.WriteFailed;
            try crashPoint(); // written, not synced
            file.sync(self.io) catch return error.WriteFailed;
        }
        try crashPoint(); // durable, not visible
        self.conf.rename(tmp, self.conf, name, self.io) catch return error.WriteFailed;
        renamed = true;
        try crashPoint(); // visible, entry not durable
        self.syncDir(dir_part orelse ".") catch return error.WriteFailed;
    }

    /// `fsync` a directory. The handle is reopened with `.iterate = true`: a
    /// plain directory handle is `O_PATH` and cannot be synced.
    fn syncDir(self: Store, sub: []const u8) !void {
        var d = try self.conf.openDir(self.io, sub, .{ .iterate = true });
        defer d.close(self.io);
        const as_file = std.Io.File{ .handle = d.handle, .flags = .{ .nonblocking = false } };
        try as_file.sync(self.io);
    }
};

/// Refuse to write what could not be loaded again: bounds first, then a parse
/// of `text` that must give back the model it was written from.
fn checkReloads(gpa: Allocator, text: []const u8, pkg: *const Package, max_bytes: usize) (StoreError)!void {
    if (text.len > max_bytes or text.len > root.max_input_len) return error.FileTooLarge;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > root.max_line_len) return error.WouldNotReload;
    var back = root.parse(gpa, text) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.WouldNotReload,
    };
    defer back.deinit(gpa);
    if (!eqlOnDisk(&back, pkg)) return error.WouldNotReload;
}

/// `Package.eql` that ignores options with no value. `del_list` of the last
/// entry leaves such an option in libuci's model too (measured: `uci show`
/// prints `net.lan.dns=`), but no text can say it, so the file has none.
pub fn eqlOnDisk(a: *const Package, b: *const Package) bool {
    var ia: usize = 0;
    var ib: usize = 0;
    while (true) {
        if (ia >= a.sections.len or ib >= b.sections.len) return ia >= a.sections.len and ib >= b.sections.len;
        const sa = &a.sections[ia];
        const sb = &b.sections[ib];
        ia += 1;
        ib += 1;
        if (!std.mem.eql(u8, sa.type, sb.type) or sa.anonymous != sb.anonymous) return false;
        if ((sa.name == null) != (sb.name == null)) return false;
        if (sa.name) |n| if (!std.mem.eql(u8, n, sb.name.?)) return false;
        var oa: usize = 0;
        var ob: usize = 0;
        while (true) {
            while (oa < sa.options.len and sa.options[oa].values.len == 0) oa += 1;
            while (ob < sb.options.len and sb.options[ob].values.len == 0) ob += 1;
            if (oa >= sa.options.len or ob >= sb.options.len) {
                if (oa < sa.options.len or ob < sb.options.len) return false;
                break;
            }
            if (!sa.options[oa].eql(&sb.options[ob])) return false;
            oa += 1;
            ob += 1;
        }
    }
}

// ── crash injection (tests only) ────────────────────────────────────────────

pub const crash_hook = if (builtin.is_test) struct {
    pub var at: ?u32 = null;
    pub var tick: u32 = 0;
    pub fn arm(k: ?u32) void {
        at = k;
        tick = 0;
    }
} else struct {};

fn crashPoint() CrashError!void {
    if (!builtin.is_test) return;
    if (crash_hook.at) |k| {
        crash_hook.tick += 1;
        if (crash_hook.tick == k) return error.SimulatedCrash;
    }
}
