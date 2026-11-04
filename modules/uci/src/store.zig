// SPDX-License-Identifier: MIT

//! The file layer of `uci`: load a package from a config directory, overlay
//! its staged delta, and write it back with `commit` -- a temp file in the same
//! directory, `fsync`, `chmod`, `rename(2)` over the old file, `fsync` of the
//! directory (so a crash leaves the old file or the new one, never a mixture,
//! and a `commit` that returned is on stable media).
//!
//! Clean-room: behaviour from running the real `uci` binary as a black box
//! (`tools/capture-store.py`, `strace -f` of one `uci commit`); no libuci source
//! was read. Measured and kept: a commit replaces the file (new inode) and keeps
//! its mode; a file created by `import` is `0600`; a committed file has no
//! `package` line; after a commit or `revert` the delta file stays, empty;
//! `import` (without `-m`) writes the package at once and leaves the delta
//! alone; a FIFO or directory named as a package is "not found"; a symlink is
//! followed (and the link stays a link); the binary takes `flock(LOCK_EX)` on the
//! config file for a commit and `LOCK_SH` for a load, and `uci get` waits for
//! another process's exclusive lock (2 s in the measurement). Steps of its
//! commit: write temp `.<pkg>.uci-XXXXXX`, fsync, chmod, rename; no directory
//! fsync.
//!
//! Deliberate differences, all on the safe side: a package name with a `/` or
//! `..` is refused (the binary refuses it too), a symlink is followed only when
//! its target is a plain name in the same directory (the binary also follows
//! `../outside`; `allow_paths` allows a relative target), the lock wait is
//! bounded (`Options.lock_timeout_ms`), the config file's directory is fsynced,
//! and a file `parse` could not read back is never written.
//!
//! The windows that remain, plainly:
//! - a crash after the rename and before the delta is emptied leaves the new
//!   file AND the old delta: `loadStaged`/`commitStaged` then replay it. Records
//!   that set or delete by name are idempotent; an anonymous `add` is added a
//!   second time and an index delete hits whatever sits at that index. The
//!   error `StagedNotCleared` (and `CommittedNotDurable`) say "the new file is
//!   in place": NEVER retry `commitStaged` on either; `revert` the delta
//!   instead, or `loadStaged` and look.
//! - the lock is advisory and is taken on the config file: a process that does
//!   not honour `flock` is not excluded, and a NEW package (no file yet) has no
//!   lock at all: two creators race, the last `rename` wins, and stale temps are
//!   not reaped then. After the lock is won the file's inode is compared with
//!   the path's and the lock retried if a rename got in between; a rename right
//!   after that check is the binary's own window too. `rename` makes readers see
//!   the old or the new file either way.
//! - a lost update is refused only for an `Editor` commit (`commitEditor` /
//!   `Session.commit` compare a `Stamp` of inode, size and mtime taken before
//!   the load with the file under the lock: `ChangedOnDisk`). `commit` of a bare
//!   model has nothing to compare with and `replace` overwrites by definition.
//! - two `Store`s with different config directories that share a save directory
//!   do not lock each other's delta files.
//! - `fsync` is as honest as the medium; ownership is not preserved (the mode is).
//!   `revert` fsyncs the truncated delta file too (a size change; no directory entry
//!   changes), so a returned `commit` or `revert` is on stable media.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const edit = @import("edit.zig");
const diff = @import("diff.zig");
const Allocator = std.mem.Allocator;
const Package = root.Package;

pub const StoreError = error{
    /// The package name is empty, too long or has a character outside
    /// `A-Za-z0-9_-` (with `Options.allow_paths`: empty, over 255 bytes, or a NUL).
    /// Also `saveEditor`: a name no delta record can carry (`diff.deltaNameOk`:
    /// a leading `-`, or a `.`, `=`, space or `'`), and a commit or save whose
    /// temp file name would pass the file system's name limit. Nothing was written.
    InvalidPackageName,
    /// The file is absent. Only this -- EMFILE, EIO, EACCES and the rest are
    /// `ReadFailed`/`AccessDenied`, never "absent".
    PackageNotFound,
    /// The name is a directory, FIFO, device, a dangling or chained symlink, or
    /// a symlink whose target leaves the directory. Nothing was read.
    NotRegularFile,
    /// The file is over `Options.max_bytes`, or `serialize` produced more than
    /// that. Nothing was read in full or written.
    FileTooLarge,
    AccessDenied,
    ReadFailed,
    /// Nothing visible changed: the temp file is removed, the old file intact.
    WriteFailed,
    /// The new text would not read back as the same package (a line over
    /// `max_line_len`, text over `max_input_len`, or a model `parse` reads
    /// differently). For `saveEditor`: the delta would not replay to the
    /// editor's state, or would cost more than `edit.max_delta_work` to replay
    /// (a reshuffle of thousands of sections). Nothing was written and the old
    /// delta is in place.
    WouldNotReload,
    /// The new file is VISIBLE, but fsync of its directory failed: it may not
    /// survive a power loss. The delta was cleared. Do not retry `commitStaged`.
    /// If the delta could not be emptied either, `StagedNotCleared` is returned
    /// instead (it wins; durability is then unknown too).
    CommittedNotDurable,
    /// The new file is VISIBLE, but emptying the package's delta failed (the
    /// directory fsync may also have failed: this error takes precedence). Do
    /// not retry `commitStaged`: it would replay the delta. `revert`.
    StagedNotCleared,
    /// `commitEditor`: the file is not the one the editor was loaded from
    /// (another process committed in between). Nothing was written. Reload and
    /// redo, or overwrite on purpose with `replace`.
    ChangedOnDisk,
    /// Another process held the package's exclusive `flock` for longer than
    /// `Options.lock_timeout_ms`. Nothing was changed.
    LockTimeout,
    /// An operation that writes a delta file on a `Store` without `save`.
    NoSaveDirectory,
    /// The kernel refused `flock` itself (ENOLCK, locking unsupported on this
    /// file system), as opposed to the lock being held by someone else
    /// (`LockTimeout`). Nothing was changed.
    LockFailed,
    OutOfMemory,
};

pub const Options = struct {
    /// Let a package name be a relative path (`sub/dir/net`, even with `..`)
    /// or absolute. Off by default: a name that comes from a request or a
    /// message must not leave the config directory.
    allow_paths: bool = false,
    /// Largest file read or written, in bytes.
    max_bytes: usize = root.max_input_len,
    /// How long a writer waits for another process's `flock` on the package,
    /// in milliseconds (polled every 20 ms). 0 = fail at once.
    lock_timeout_ms: u32 = 5000,
};

pub const LoadError = StoreError || root.ParseError;
pub const StagedError = LoadError || edit.DeltaError;
pub const CommitError = StoreError || root.SerializeError || edit.EditError;

/// What a config file looked like when an editor was loaded from it: inode,
/// size and mtime. `Store.stamp` takes one; `commitEditor` compares it under the
/// lock. A rename-based writer (the binary, this module) changes the inode.
pub const Stamp = struct {
    inode: @FieldType(std.Io.File.Stat, "inode"),
    size: u64,
    mtime: std.Io.Timestamp,

    fn of(st: std.Io.File.Stat) Stamp {
        return .{ .inode = st.inode, .size = st.size, .mtime = st.mtime };
    }
    pub fn eql(a: Stamp, b: Stamp) bool {
        return a.inode == b.inode and a.size == b.size and std.meta.eql(a.mtime, b.mtime);
    }
};

fn stampsMatch(a: ?Stamp, b: ?Stamp) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return a.?.eql(b.?);
}

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

const tmp_infix = ".uci-tmp-";
const tmp_rand_len = 16;
/// The longest temp name `isTempOf` can accept: `.` + a base name of up to 255
/// bytes (`allow_paths`) + infix + digits.
const max_temp_name = 1 + 255 + tmp_infix.len + tmp_rand_len;

/// What the commit does, in order; the test seam records these.
pub const Step = enum { write, chmod, fsync_file, rename, fsync_dir, fsync_delta };

pub const Store = struct {
    io: std.Io,
    /// The config directory (`/etc/config`).
    conf: std.Io.Dir,
    /// The save directory with the staged deltas (`/tmp/.uci`); null = no
    /// staging: nothing is overlaid and `commit` has nothing to clear.
    save: ?std.Io.Dir = null,
    /// `uci -p`: more directories whose deltas are replayed BEFORE `save`'s,
    /// in order (measured). Read only.
    extra_save: []const std.Io.Dir = &.{},
    /// `uci -C`: a directory whose file of the package's name replaces the
    /// config file in `loadView` (measured: reading only; a commit still writes
    /// the config file's own content plus the delta).
    override: ?std.Io.Dir = null,
    options: Options = .{},

    fn checkName(self: Store, name: []const u8) StoreError!void {
        // a control byte (a newline is a record separator in a delta) never
        for (name) |c| if (c < 0x20 or c == 0x7f) return error.InvalidPackageName;
        if (self.options.allow_paths) {
            if (name.len == 0 or name.len > 255 or std.mem.indexOfScalar(u8, name, 0) != null) return error.InvalidPackageName;
        } else if (!validPackageName(name)) return error.InvalidPackageName;
    }

    /// Where the config file `name` really is: `name` itself, or, if it is a
    /// symlink, its target when that is a plain name in the same directory
    /// (with `allow_paths`, a relative path joined to the link's directory). A
    /// chained link, a dangling one, or a target that leaves the directory is
    /// `NotRegularFile`. Absent `name`: returned as is. The result is written
    /// into `buf`.
    fn resolve(self: Store, dir: std.Io.Dir, name: []const u8, buf: []u8) StoreError![]const u8 {
        const st = dir.statFile(self.io, name, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => return name,
            .denied => return error.AccessDenied,
            .other => return error.ReadFailed,
        };
        if (st.kind != .sym_link) return name;
        var lb: [256]u8 = undefined;
        const n = dir.readLink(self.io, name, &lb) catch return error.NotRegularFile;
        const t = lb[0..n];
        if (t.len == 0 or std.mem.eql(u8, t, ".") or std.mem.eql(u8, t, "..") or t[0] == '/') return error.NotRegularFile;
        var target: []const u8 = t;
        if (std.mem.indexOfScalar(u8, t, '/') != null) {
            if (!self.options.allow_paths) return error.NotRegularFile;
            const dp = std.fs.path.dirname(name) orelse "";
            target = std.fmt.bufPrint(buf, "{s}{s}{s}", .{ dp, if (dp.len > 0) "/" else "", t }) catch return error.NotRegularFile;
        } else if (std.fs.path.dirname(name)) |dp| {
            target = std.fmt.bufPrint(buf, "{s}/{s}", .{ dp, t }) catch return error.NotRegularFile;
        } else {
            if (t.len > buf.len) return error.NotRegularFile;
            @memcpy(buf[0..t.len], t);
            target = buf[0..t.len];
        }
        const st2 = dir.statFile(self.io, target, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => return error.NotRegularFile,
            .denied => return error.AccessDenied,
            .other => return error.ReadFailed,
        };
        if (st2.kind != .file) return error.NotRegularFile;
        return target;
    }

    /// The bytes of a regular file `name` in `dir`: null if it is absent,
    /// `NotRegularFile` for anything else that exists (a FIFO would block
    /// `open` and `/dev/zero` never ends; a symlink is not followed here), and
    /// an error for every failure to look or read. The path is `lstat`ed first
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

    /// `readRegular` on a config file, through `resolve`.
    fn readConf(self: Store, gpa: Allocator, dir: std.Io.Dir, name: []const u8) StoreError!?[]u8 {
        var rb: [512]u8 = undefined;
        return self.readRegular(gpa, dir, try self.resolve(dir, name, &rb));
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

    /// The stamp of the config file `name` (null: there is none), to be taken
    /// BEFORE the load it guards and handed to `commitEditor`.
    pub fn stamp(self: Store, name: []const u8) StoreError!?Stamp {
        try self.checkName(name);
        var rb: [512]u8 = undefined;
        const target = try self.resolve(self.conf, name, &rb);
        const st = self.conf.statFile(self.io, target, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => return null,
            .denied => return error.AccessDenied,
            .other => return error.ReadFailed,
        };
        if (st.kind != .file) return error.NotRegularFile;
        return Stamp.of(st);
    }

    /// The committed file of `name`, parsed. `PackageNotFound` if there is none.
    pub fn load(self: Store, gpa: Allocator, name: []const u8, diag: ?*root.Diagnostics) LoadError!Package {
        try self.checkName(name);
        const bytes = (try self.readConf(gpa, self.conf, name)) orelse return error.PackageNotFound;
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

    /// The deltas of the `extra_save` directories (in order), then `save`'s,
    /// replayed on `ed`. Missing or empty files change nothing.
    pub fn applyDeltas(self: Store, gpa: Allocator, name: []const u8, ed: *edit.Editor, diag: ?*root.Diagnostics) StagedError!void {
        try self.applyExtras(gpa, name, ed, diag);
        const bytes = (try self.staged(gpa, name)) orelse return;
        defer gpa.free(bytes);
        try ed.applyDelta(name, bytes, diag);
    }

    fn applyExtras(self: Store, gpa: Allocator, name: []const u8, ed: *edit.Editor, diag: ?*root.Diagnostics) StagedError!void {
        for (self.extra_save) |d| {
            const bytes = (try self.readRegular(gpa, d, name)) orelse continue;
            defer gpa.free(bytes);
            try ed.applyDelta(name, bytes, diag);
        }
    }

    /// An `Editor` on the committed file plus the `extra_save` deltas, WITHOUT
    /// `save`'s delta: the state `revert` and `saveEditor` measure against.
    /// Its anonymous ids are the ones the delta records use. Caller deinits.
    pub fn baseEditor(self: Store, gpa: Allocator, name: []const u8, diag: ?*root.Diagnostics) StagedError!edit.Editor {
        var base = try self.load(gpa, name, diag);
        defer base.deinit(gpa);
        var ed = try edit.Editor.init(gpa, &base);
        errdefer ed.deinit();
        try self.applyExtras(gpa, name, &ed, diag);
        return ed;
    }

    /// What `uci get`/`uci show` report: the committed file with the staged
    /// deltas (`extra_save`, then `save`) replayed on it.
    pub fn loadStaged(self: Store, gpa: Allocator, name: []const u8, diag: ?*root.Diagnostics) StagedError!Package {
        var base = try self.load(gpa, name, diag);
        defer base.deinit(gpa);
        var ed = try edit.Editor.init(gpa, &base);
        defer ed.deinit();
        try self.applyDeltas(gpa, name, &ed, diag);
        var out = try ed.toPackage(gpa);
        out.name = null;
        return out;
    }

    /// `loadStaged` with `uci -C`: a file of the package's name in `override`
    /// replaces the committed file as the base of the view.
    pub fn loadView(self: Store, gpa: Allocator, name: []const u8, diag: ?*root.Diagnostics) StagedError!Package {
        const ov = self.override orelse return self.loadStaged(gpa, name, diag);
        try self.checkName(name);
        const bytes = (try self.readRegular(gpa, ov, name)) orelse return self.loadStaged(gpa, name, diag);
        defer gpa.free(bytes);
        var base = try root.parseDiag(gpa, bytes, diag);
        defer base.deinit(gpa);
        var ed = try edit.Editor.init(gpa, &base);
        defer ed.deinit();
        try self.applyDeltas(gpa, name, &ed, diag);
        return ed.toPackage(gpa);
    }

    /// `uci revert <pkg>`: discard the staged changes of the package by
    /// emptying its delta file (the binary leaves it there, empty; measured).
    /// No delta file, or no save directory: nothing to do. The name is
    /// `lstat`ed (a symlink, FIFO or directory is `NotRegularFile`), then
    /// opened without following links and WITHOUT creating, then truncated.
    pub fn revert(self: Store, name: []const u8) StoreError!void {
        try self.checkName(name);
        const save = self.save orelse return;
        const st = save.statFile(self.io, name, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => return,
            .denied => return error.AccessDenied,
            .other => return error.WriteFailed,
        };
        if (st.kind != .file) return error.NotRegularFile;
        const f = save.openFile(self.io, name, .{ .mode = .write_only, .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => return,
            .denied => return error.AccessDenied,
            else => return if (std.mem.eql(u8, @errorName(e), "SymLinkLoop")) error.NotRegularFile else error.WriteFailed,
        };
        defer f.close(self.io);
        const st2 = f.stat(self.io) catch return error.WriteFailed;
        if (st2.kind != .file) return error.NotRegularFile;
        f.setLength(self.io, 0) catch return error.WriteFailed;
        // The truncation is a size change of this file, so the file's fsync makes
        // it durable; no directory entry changes. Without it the old delta could
        // come back after a power loss next to a durable new config.
        if (!skipStep(.fsync_delta)) {
            f.sync(self.io) catch return error.WriteFailed;
            recStep(.fsync_delta);
        }
    }

    // ── locking ──────────────────────────────────────────────────────────

    /// Take the package's exclusive `flock`, as the binary does for a commit
    /// (measured with strace: `flock(LOCK_EX)` on the config file). Waits up to
    /// `Options.lock_timeout_ms`. A package with no file yet has nothing to lock.
    /// The lock lives as long as the returned file; `close` releases it.
    fn lockPkg(self: Store, name: []const u8) StoreError!?std.Io.File {
        var rb: [512]u8 = undefined;
        const target = try self.resolve(self.conf, name, &rb);
        // never `open` a FIFO: stat first (a directory or device is refused too)
        const st = self.conf.statFile(self.io, target, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => return null,
            .denied => return error.AccessDenied,
            .other => return error.ReadFailed,
        };
        if (st.kind != .file) return error.NotRegularFile;
        var waited: u32 = 0;
        while (true) {
            const f = self.conf.openFile(self.io, target, .{ .mode = .read_only, .follow_symlinks = false }) catch |e| switch (classify(e)) {
                .absent => return null,
                .denied => return error.AccessDenied,
                .other => return error.ReadFailed,
            };
            if (builtin.is_test) if (crash_hook.after_open) |h| h();
            const got = (if (builtin.is_test and crash_hook.fail_trylock) @as(anyerror!bool, error.Unexpected) else f.tryLock(self.io, .exclusive)) catch {
                f.close(self.io);
                return error.LockFailed;
            };
            if (got) {
                // won the lock on an inode that may have been renamed over
                // between open and lock: it must still be the file at the path
                const a = f.stat(self.io) catch {
                    f.close(self.io);
                    return error.ReadFailed;
                };
                const b = self.conf.statFile(self.io, target, .{ .follow_symlinks = false }) catch |e| {
                    f.close(self.io);
                    if (classify(e) == .absent) return null;
                    return error.ReadFailed;
                };
                if (a.inode == b.inode) return f;
                if (builtin.is_test) crash_hook.lock_retries += 1;
            }
            f.close(self.io);
            if (waited >= self.options.lock_timeout_ms) return error.LockTimeout;
            if (!got) self.io.sleep(.fromMilliseconds(20), .awake) catch {};
            waited +|= 20; // saturating: a huge timeout must not wrap
        }
    }

    // ── commit ───────────────────────────────────────────────────────────

    /// `uci commit <pkg>` from a BARE model: write `pkg` as the package's file
    /// (atomically, durably; see the module comment), then empty its delta,
    /// under the package's `flock`. There is no load to compare with, so this
    /// does not notice another process's commit in between: use `commitEditor`
    /// (compares a `Stamp`) when the model came from an editor, `replace` to
    /// overwrite on purpose. `pkg.name` is not written (a committed file has no
    /// `package` line). On `CommittedNotDurable` and `StagedNotCleared` the new
    /// file is visible: do not retry a staged commit.
    pub fn commit(self: Store, gpa: Allocator, name: []const u8, pkg: *const Package) CommitError!void {
        try self.checkName(name);
        const lock = try self.lockPkg(name);
        defer if (lock) |f| f.close(self.io);
        try self.commitLocked(gpa, name, pkg, lock != null);
    }

    fn commitLocked(self: Store, gpa: Allocator, name: []const u8, pkg: *const Package, locked: bool) CommitError!void {
        var durable = true;
        self.replaceLocked(gpa, name, pkg, locked) catch |e| switch (e) {
            error.CommittedNotDurable => durable = false,
            else => return e,
        };
        try crashPoint(); // replaced, delta not yet cleared
        // precedence: a delta left behind is the worse news (documented on both errors)
        self.revert(name) catch return error.StagedNotCleared;
        if (!durable) return error.CommittedNotDurable;
    }

    /// `commit` of an `Editor`'s current state, refused with `ChangedOnDisk`
    /// when the file is no longer the one the editor was loaded from. `expect`
    /// is `stamp(name)` taken BEFORE the load (null: the file did not exist).
    /// BREAKING 2026-11-04: the parameter is new.
    pub fn commitEditor(self: Store, gpa: Allocator, name: []const u8, ed: *const edit.Editor, expect: ?Stamp) CommitError!void {
        try self.checkName(name);
        var pkg = try ed.toPackage(gpa);
        defer pkg.deinit(gpa);
        const lock = try self.lockPkg(name);
        defer if (lock) |f| f.close(self.io);
        if (!stampsMatch(expect, try self.stamp(name))) return error.ChangedOnDisk;
        try self.commitLocked(gpa, name, &pkg, lock != null);
    }

    /// `uci commit <pkg>` for a package edited by other processes: replay the
    /// delta on the committed file and write the result, under the lock. No
    /// pending delta: nothing is written (the binary also returns success).
    pub fn commitStaged(self: Store, gpa: Allocator, name: []const u8, diag: ?*root.Diagnostics) (StagedError || CommitError)!void {
        try self.checkName(name);
        const lock = try self.lockPkg(name);
        defer if (lock) |f| f.close(self.io);
        if (!try self.hasStaged(gpa, name)) {
            // Still `PackageNotFound` for a package that does not exist.
            var p = try self.load(gpa, name, diag);
            p.deinit(gpa);
            return;
        }
        var live = try self.loadStaged(gpa, name, diag);
        defer live.deinit(gpa);
        try self.commitLocked(gpa, name, &live, lock != null);
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

    /// Write `pkg` as the file of `name` (no delta handling), under the lock:
    /// the atomic part. OVERWRITES whatever is on disk (no `ChangedOnDisk`
    /// check). `CommittedNotDurable` means the file is in place.
    pub fn replace(self: Store, gpa: Allocator, name: []const u8, pkg: *const Package) CommitError!void {
        try self.checkName(name);
        const lock = try self.lockPkg(name);
        defer if (lock) |f| f.close(self.io);
        try self.replaceLocked(gpa, name, pkg, lock != null);
    }

    fn replaceLocked(self: Store, gpa: Allocator, name: []const u8, pkg: *const Package, locked: bool) CommitError!void {
        var view = pkg.*;
        view.name = null;
        const text = try root.serialize(gpa, &view);
        defer gpa.free(text);
        try checkReloads(gpa, text, &view, self.options.max_bytes);

        var rb: [512]u8 = undefined;
        const target = try self.resolve(self.conf, name, &rb);
        // Keep the mode of the file being replaced; a new file is 0600 (what
        // `uci import` creates, measured).
        const st = self.conf.statFile(self.io, target, .{ .follow_symlinks = false }) catch |e| switch (classify(e)) {
            .absent => null,
            .denied => return error.AccessDenied,
            .other => return error.WriteFailed,
        };
        var perms: std.Io.File.Permissions = @fromBackingInt(@intCast(0o600));
        if (st) |s| {
            if (s.kind != .file) return error.NotRegularFile;
            perms = s.permissions;
        }
        try self.writeAtomic(self.conf, target, text, perms, locked);
    }

    /// `save`: write the staged changes of `ed` (relative to the committed
    /// file plus the `extra_save` deltas) as the package's delta file, so
    /// another process (or a restart) sees them. Replaces the file's content;
    /// `ed` must have been built from this store's files (`Session` does).
    pub fn saveEditor(self: Store, gpa: Allocator, name: []const u8, ed: *const edit.Editor) (StagedError || CommitError)!void {
        try self.checkName(name);
        const save = self.save orelse return error.NoSaveDirectory;
        const lock = try self.lockPkg(name);
        defer if (lock) |f| f.close(self.io);
        var bed = try self.baseEditor(gpa, name, null);
        defer bed.deinit();
        if (!diff.deltaNameOk(name)) return error.InvalidPackageName;
        const rec = diff.diffRecords(gpa, &bed, ed, name, null) catch |e| switch (e) {
            error.WorkLimitExceeded => return error.WouldNotReload,
            else => |x| return x,
        };
        defer gpa.free(rec);
        if (rec.len > self.options.max_bytes) return error.FileTooLarge;
        try checkDeltaReloads(gpa, &bed, ed, name, rec);
        // an existing delta file keeps its mode; a symlink/FIFO there is refused
        var perms: std.Io.File.Permissions = @fromBackingInt(@intCast(0o644));
        if (save.statFile(self.io, name, .{ .follow_symlinks = false })) |s| {
            if (s.kind != .file) return error.NotRegularFile;
            perms = s.permissions;
        } else |e| switch (classify(e)) {
            .absent => {},
            .denied => return error.AccessDenied,
            .other => return error.WriteFailed,
        }
        try self.writeAtomic(save, name, rec, perms, lock != null);
    }

    /// temp file + write + chmod + fsync + rename + directory fsync, in `dir`.
    /// Reaps this package's stale temps first. The failure modes: before the
    /// rename, `WriteFailed`/`AccessDenied` with the temp removed and the old
    /// file intact; after it, `CommittedNotDurable`.
    fn writeAtomic(self: Store, dir: std.Io.Dir, target: []const u8, text: []const u8, perms: std.Io.File.Permissions, locked: bool) CommitError!void {
        const io = self.io;
        const dir_part = std.fs.path.dirname(target);
        const base = std.fs.path.basename(target);
        // only under the lock: without one (a new package) a temp of that name
        // may be another creator's live one
        if (locked) self.reapTemps(dir, dir_part orelse ".", base);

        var tbuf: [768]u8 = undefined;
        var tmp: []const u8 = undefined;
        var file: std.Io.File = undefined;
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            if (attempt == 8) return error.WriteFailed;
            var rnd: [tmp_rand_len / 2]u8 = undefined;
            io.random(&rnd);
            const hex = std.fmt.bytesToHex(rnd, .lower);
            tmp = std.fmt.bufPrint(&tbuf, "{s}{s}.{s}{s}{s}", .{
                dir_part orelse "",
                if (dir_part != null) "/" else "",
                base,
                tmp_infix,
                &hex,
            }) catch return error.InvalidPackageName;
            file = dir.createFile(io, tmp, .{ .exclusive = true, .permissions = @fromBackingInt(@intCast(0o600)) }) catch |e| {
                if (std.mem.eql(u8, @errorName(e), "PathAlreadyExists")) continue;
                if (std.mem.eql(u8, @errorName(e), "NameTooLong")) return error.InvalidPackageName;
                return switch (classify(e)) {
                    .denied => error.AccessDenied,
                    else => error.WriteFailed,
                };
            };
            break;
        }
        var renamed = false;
        // a simulated crash leaves its debris, like a real one
        defer if (!renamed and !(builtin.is_test and crash_hook.at != null)) dir.deleteFile(io, tmp) catch {};
        {
            defer file.close(io);
            if (builtin.is_test and crash_hook.fail_write) {
                file.writeStreamingAll(io, text[0 .. text.len / 2]) catch {};
                return error.WriteFailed; // a short write / ENOSPC
            }
            file.writeStreamingAll(io, text) catch return error.WriteFailed;
            recStep(.write);
            if (!skipStep(.chmod)) {
                file.setPermissions(io, perms) catch return error.WriteFailed;
                recStep(.chmod);
            }
            try crashPoint(); // written, not synced
            if (!skipStep(.fsync_file)) {
                file.sync(io) catch return error.WriteFailed;
                recStep(.fsync_file);
            }
        }
        try crashPoint(); // durable, not visible
        dir.rename(tmp, dir, target, io) catch return error.WriteFailed;
        recStep(.rename);
        renamed = true;
        try crashPoint(); // visible, entry not durable
        if (!skipStep(.fsync_dir)) {
            self.syncDir(dir, dir_part orelse ".") catch return error.CommittedNotDurable;
            recStep(.fsync_dir);
        }
        try crashPoint(); // durable
    }

    /// Delete this package's stale temp files (`.<base>.uci-tmp-` + 16 hex
    /// digits, regular files only) left by a crashed commit. Runs under the
    /// package lock; best effort, at most 16 per call.
    fn reapTemps(self: Store, dir: std.Io.Dir, sub: []const u8, base: []const u8) void {
        var d = dir.openDir(self.io, sub, .{ .iterate = true }) catch return;
        defer d.close(self.io);
        var names: [16][max_temp_name]u8 = undefined;
        var lens: [16]usize = undefined;
        var n: usize = 0;
        var it = d.iterate();
        while (it.next(self.io) catch return) |e| {
            if (n == names.len) break;
            if (e.kind != .file) continue; // regular files only (a link or FIFO is left alone)
            if (!isTempOf(e.name, base)) continue;
            if (e.name.len > names[n].len) continue;
            @memcpy(names[n][0..e.name.len], e.name);
            lens[n] = e.name.len;
            n += 1;
        }
        for (0..n) |i| d.deleteFile(self.io, names[i][0..lens[i]]) catch {};
    }

    /// `fsync` a directory. The handle is reopened with `.iterate = true`: a
    /// plain directory handle is `O_PATH` and cannot be synced.
    fn syncDir(self: Store, dir: std.Io.Dir, sub: []const u8) !void {
        if (builtin.is_test and crash_hook.fail_dir_sync) return error.InputOutput;
        var d = try dir.openDir(self.io, sub, .{ .iterate = true });
        defer d.close(self.io);
        const as_file = std.Io.File{ .handle = d.handle, .flags = .{ .nonblocking = false } };
        try as_file.sync(self.io);
    }
};

/// `.<base>.uci-tmp-<16 lower-case hex digits>` exactly.
pub fn isTempOf(name: []const u8, base: []const u8) bool {
    const want = 1 + base.len + tmp_infix.len + tmp_rand_len;
    if (name.len != want or name[0] != '.') return false;
    if (!std.mem.eql(u8, name[1 .. 1 + base.len], base)) return false;
    if (!std.mem.eql(u8, name[1 + base.len ..][0..tmp_infix.len], tmp_infix)) return false;
    for (name[1 + base.len + tmp_infix.len ..]) |c| if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return false;
    return true;
}

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

/// `save`'s own check: replay `rec` on `base` (the editor a fresh load of the
/// package would start from) and demand the editor's state `want`: the same
/// sections in the same order, the same options as a set (a replayed change may
/// move an option to the end of its section). A replay failure of any kind other
/// than memory is `WouldNotReload`.
fn checkDeltaReloads(gpa: Allocator, base: *edit.Editor, want: *const edit.Editor, name: []const u8, rec: []const u8) (StoreError || edit.EditError)!void {
    base.applyDelta(name, rec, null) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.WouldNotReload,
    };
    var a = try base.toPackage(gpa);
    defer a.deinit(gpa);
    var b = try want.toPackage(gpa);
    defer b.deinit(gpa);
    if (!eqlSameSet(&a, &b)) return error.WouldNotReload;
}

fn eqlSameSet(a: *const Package, b: *const Package) bool {
    if (a.sections.len != b.sections.len) return false;
    for (a.sections, b.sections) |*sa, *sb| {
        if (!std.mem.eql(u8, sa.type, sb.type) or sa.anonymous != sb.anonymous) return false;
        if ((sa.name == null) != (sb.name == null)) return false;
        if (sa.name) |n| if (!std.mem.eql(u8, n, sb.name.?)) return false;
        var na: usize = 0;
        for (sa.options) |*oa| {
            if (oa.values.len == 0) continue;
            na += 1;
            const ob = sb.option(oa.key) orelse return false;
            if (!oa.eql(ob)) return false;
        }
        var nb: usize = 0;
        for (sb.options) |*ob| nb += @intFromBool(ob.values.len != 0);
        if (na != nb) return false;
    }
    return true;
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

// ── test seams ──────────────────────────────────────────────────────────────
// Compiled out of every non-test build.

pub const crash_hook = if (builtin.is_test) struct {
    /// Stop with `SimulatedCrash` at the k-th crash point (1-based).
    pub var at: ?u32 = null;
    /// Set when the armed crash point fired (it surfaces as `WriteFailed`).
    pub var tripped: bool = false;
    /// Called after the lock file is opened and before it is locked.
    pub var after_open: ?*const fn () void = null;
    /// How often the inode re-check sent `lockPkg` round again.
    pub var lock_retries: u32 = 0;
    pub var tick: u32 = 0;
    /// Write half of the text and fail, as ENOSPC would.
    pub var fail_write: bool = false;
    /// Make `tryLock` fail with an error that is not "held".
    pub var fail_trylock: bool = false;
    /// Make the directory `fsync` fail.
    pub var fail_dir_sync: bool = false;
    /// Record the steps performed, in order.
    pub var recording: bool = false;
    pub var steps: [16]Step = undefined;
    pub var n_steps: usize = 0;
    /// A mutant: leave this step out.
    pub var skip: ?Step = null;
    pub fn arm(k: ?u32) void {
        at = k;
        tick = 0;
        tripped = false;
    }
    pub fn startRecording() void {
        recording = true;
        n_steps = 0;
    }
} else struct {};

/// A test build can stop a commit at a crash point. It surfaces as an ordinary
/// `WriteFailed` plus `crash_hook.tripped`, so the public error set is the same
/// in a consumer's test build and in a normal one.
fn crashPoint() StoreError!void {
    if (!builtin.is_test) return;
    if (crash_hook.at) |k| {
        crash_hook.tick += 1;
        if (crash_hook.tick == k) {
            crash_hook.tripped = true;
            return error.WriteFailed;
        }
    }
}

inline fn skipStep(s: Step) bool {
    if (!builtin.is_test) return false;
    return crash_hook.skip != null and crash_hook.skip.? == s;
}

inline fn recStep(s: Step) void {
    if (!builtin.is_test) return;
    if (crash_hook.recording and crash_hook.n_steps < crash_hook.steps.len) {
        crash_hook.steps[crash_hook.n_steps] = s;
        crash_hook.n_steps += 1;
    }
}
