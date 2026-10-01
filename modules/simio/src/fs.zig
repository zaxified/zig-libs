// SPDX-License-Identifier: MIT

//! The simulated file system behind `std.Io.Dir` and `std.Io.File`: one tree
//! per host, and a durability model that decides what a crash leaves behind.
//!
//! **What survives a crash** (the model real crash bugs hide behind — ALICE,
//! OSDI 2014):
//!
//! - *File data.* Each file keeps its contents as of the last `File.sync`
//!   plus the writes and truncations since, in order. On a crash each later
//!   write survives sector by sector (`Options.fs.sector_bytes`), each sector
//!   independently with `crash_keep_permille`, and so does each truncation:
//!   lost, kept, torn and reordered writes are all possible outcomes.
//! - *Names.* Creating, deleting and renaming are journaled metadata
//!   operations. They become durable when the directory they change is
//!   synced (`.strict`, POSIX's minimum: syncing a file does not make its
//!   name durable), or when anything is synced (`.journal`, ext4-like). On a
//!   crash a random prefix of the remaining journal survives, whole
//!   operations at a time, so a rename is never half done.
//!
//! A sync of a directory goes through `File.sync` on its handle, as on Linux
//! (`File{ .handle = dir.handle }`).
//!
//! **Faults:** one-shot `error.InputOutput` on the next read, write or sync
//! of a host (`Fault.disk_error`), silent bit rot in a stored file
//! (`Fault.bit_rot`), and a capacity per host (`HostOptions.disk_bytes`) past
//! which writes fail with `error.NoSpaceLeft`.
//!
//! Symbolic links are followed in every component (at most 40, then
//! `SymLinkLoop`) and in the last one where POSIX does (`stat`, `open`,
//! `realpath`), not where it does not (`lstat`, `unlink`, `rename`,
//! `readlink`); a link and a hard link are names, journaled like any other.
//! Permissions, owners and timestamps are stored and reported, not enforced.
//! Nodes are freed with the simulation.

const std = @import("std");
const netsim = @import("netsim");
const sched = @import("sched.zig");

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Prng = netsim.Prng;
const Sim = sched.Sim;
const Host = sched.Host;

pub const FsOptions = struct {
    /// When a name change becomes durable: when its directory is synced
    /// (`.strict`), or with any sync on the host (`.journal`).
    durability: enum { strict, journal } = .strict,
    /// Unit in which unsynced writes survive or vanish on a crash.
    sector_bytes: u32 = 512,
    /// Probability that one unsynced sector (or truncation) survives a crash.
    crash_keep_permille: u16 = 500,
};

const cwd_handle: Dir.Handle = std.posix.AT.FDCWD;

const DataOp = union(enum) {
    write: struct { off: u64, bytes: []u8 },
    set_len: u64,
};

/// One journaled name change: set `dir[name]` to `target`, or remove it.
const MetaOp = struct {
    group: u64,
    dir: *Node,
    name: []u8,
    target: ?*Node,
};

pub const Node = struct {
    ino: u64,
    kind: enum { file, dir, symlink },
    // files; a symlink's target
    data: std.ArrayList(u8) = .empty,
    synced: std.ArrayList(u8) = .empty,
    pending: std.ArrayList(DataOp) = .empty,
    // directories: names now, and names as a crash would find them
    entries: std.StringArrayHashMapUnmanaged(*Node) = .empty,
    durable: std.StringArrayHashMapUnmanaged(*Node) = .empty,
    parent: ?*Node = null,
    nlink: u32 = 0,
    perm: File.Permissions,
    uid: File.Uid = 0,
    gid: File.Gid = 0,
    mtime: i96 = 0,
    ctime: i96 = 0,
    atime: i96 = 0,
    lock_exclusive: bool = false,
    lock_shared: u32 = 0,

    fn freeEntries(gpa: Allocator, map: *std.StringArrayHashMapUnmanaged(*Node)) void {
        for (map.keys()) |k| gpa.free(k);
        map.deinit(gpa);
    }
};

const OpenFile = struct {
    node: *Node,
    read: bool,
    write: bool,
    pos: u64 = 0,
    lock: File.Lock = .none,
};

pub const Fs = struct {
    host: *Host,
    root: *Node,
    nodes: std.ArrayList(*Node) = .empty,
    open: std.AutoHashMapUnmanaged(Io.File.Handle, OpenFile) = .empty,
    journal: std.ArrayList(MetaOp) = .empty,
    next_group: u64 = 1,
    next_ino: u64 = 2,
    prng: Prng,
    used_bytes: u64 = 0,
    capacity: ?u64,
    fail_read: u32 = 0,
    fail_write: u32 = 0,
    fail_sync: u32 = 0,
    /// What the host's code wrote to stdout/stderr (bounded).
    console: std.ArrayList(u8) = .empty,

    pub fn init(fs: *Fs, h: *Host, seed: u64, capacity: ?u64) Allocator.Error!void {
        fs.* = .{ .host = h, .root = undefined, .prng = .init(seed ^ 0x66735f73696d2121), .capacity = capacity };
        const root = try fs.newNode(.dir);
        root.nlink = 1;
        fs.root = root;
    }

    pub fn deinit(fs: *Fs) void {
        const gpa = fs.alloc();
        for (fs.nodes.items) |n| {
            n.data.deinit(gpa);
            n.synced.deinit(gpa);
            freePending(gpa, &n.pending);
            n.pending.deinit(gpa);
            Node.freeEntries(gpa, &n.entries);
            Node.freeEntries(gpa, &n.durable);
            gpa.destroy(n);
        }
        fs.nodes.deinit(gpa);
        fs.open.deinit(gpa);
        for (fs.journal.items) |op| gpa.free(op.name);
        fs.journal.deinit(gpa);
        fs.console.deinit(gpa);
    }

    fn alloc(fs: *const Fs) Allocator {
        return fs.host.sim.gpa;
    }

    fn now(fs: *const Fs) i96 {
        return fs.host.clockNs(.real);
    }

    fn newNode(fs: *Fs, kind: @FieldType(Node, "kind")) Allocator.Error!*Node {
        const g = fs.alloc();
        try fs.nodes.ensureUnusedCapacity(g, 1);
        const n = try g.create(Node);
        const t = fs.now();
        n.* = .{
            .ino = fs.next_ino,
            .kind = kind,
            .perm = if (kind == .dir) .default_dir else .default_file,
            .mtime = t,
            .ctime = t,
            .atime = t,
        };
        fs.next_ino += 1;
        fs.nodes.appendAssumeCapacity(n);
        return n;
    }

    fn freePending(g: Allocator, list: *std.ArrayList(DataOp)) void {
        for (list.items) |op| switch (op) {
            .write => |w| g.free(w.bytes),
            .set_len => {},
        };
        list.clearRetainingCapacity();
    }

    // ── handles and paths ───────────────────────────────────────────────────

    fn newHandle(fs: *Fs, of: OpenFile) Allocator.Error!Io.File.Handle {
        const h = fs.host;
        try fs.open.ensureUnusedCapacity(fs.alloc(), 1);
        const handle = h.next_handle;
        h.next_handle += 1;
        fs.open.putAssumeCapacity(handle, of);
        return handle;
    }

    fn openOf(fs: *Fs, handle: Io.File.Handle) ?*OpenFile {
        return fs.open.getPtr(handle);
    }

    fn dirNode(fs: *Fs, dir: Dir, path: []const u8) error{ FileNotFound, NotDir }!*Node {
        if (path.len > 0 and path[0] == '/') return fs.root;
        if (dir.handle == cwd_handle) return fs.root;
        const of = fs.openOf(dir.handle) orelse return error.FileNotFound;
        if (of.node.kind != .dir) return error.NotDir;
        return of.node;
    }

    const Resolved = struct {
        /// The directory holding the last component (null for "." and "..").
        parent: ?*Node,
        name: []const u8,
        node: ?*Node,
    };

    /// Symbolic links followed in one resolution before `SymLinkLoop`
    /// (Linux's MAXSYMLINKS).
    const max_hops = 40;

    const ResolveError = error{ FileNotFound, NotDir, BadPathName, SymLinkLoop };

    /// Resolves `path`, following symbolic links in every component but the
    /// last (the `lstat` view: the result may itself be a link).
    fn resolve(fs: *Fs, dir: Dir, path: []const u8) ResolveError!Resolved {
        var hops: u8 = 0;
        return fs.resolveAt(try fs.dirNode(dir, path), path, &hops);
    }

    /// `resolve`, then through the last component too while it is a link
    /// (the `stat`/`open` view). A dangling link resolves to its target's
    /// absent name, so creating through it creates the target.
    fn resolveFollow(fs: *Fs, dir: Dir, path: []const u8) ResolveError!Resolved {
        var hops: u8 = 0;
        const r = try fs.resolveAt(try fs.dirNode(dir, path), path, &hops);
        return fs.followAt(r, &hops);
    }

    fn resolveAt(fs: *Fs, start: *Node, path: []const u8, hops: *u8) ResolveError!Resolved {
        if (path.len == 0) return error.BadPathName;
        var cur = if (path[0] == '/') fs.root else start;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        var last: ?[]const u8 = null;
        while (it.next()) |comp| {
            if (last) |prev| cur = try fs.step(cur, prev, hops);
            last = comp;
        }
        const name = last orelse return .{ .parent = null, .name = "", .node = cur }; // "/"
        if (std.mem.eql(u8, name, ".")) return .{ .parent = null, .name = "", .node = cur };
        if (std.mem.eql(u8, name, "..")) return .{ .parent = null, .name = "", .node = cur.parent orelse cur };
        return .{ .parent = cur, .name = name, .node = cur.entries.get(name) };
    }

    fn followAt(fs: *Fs, resolved: Resolved, hops: *u8) ResolveError!Resolved {
        var r = resolved;
        while (r.node) |n| {
            if (n.kind != .symlink) break;
            hops.* += 1;
            if (hops.* > max_hops) return error.SymLinkLoop;
            r = try fs.resolveAt(r.parent orelse fs.root, n.data.items, hops);
        }
        return r;
    }

    fn step(fs: *Fs, cur: *Node, comp: []const u8, hops: *u8) ResolveError!*Node {
        if (std.mem.eql(u8, comp, ".")) return cur;
        if (std.mem.eql(u8, comp, "..")) return cur.parent orelse cur;
        const entry = cur.entries.get(comp) orelse return error.FileNotFound;
        const next = (try fs.followAt(.{ .parent = cur, .name = comp, .node = entry }, hops)).node orelse
            return error.FileNotFound;
        if (next.kind != .dir) return error.NotDir;
        return next;
    }

    // ── the journal ─────────────────────────────────────────────────────────

    /// Changes a name now and journals the change. Entries own their keys.
    fn setEntry(fs: *Fs, dir: *Node, name: []const u8, target: ?*Node, group: u64) Allocator.Error!void {
        const g = fs.alloc();
        try fs.journal.ensureUnusedCapacity(g, 1);
        const jname = try g.dupe(u8, name);
        errdefer g.free(jname);
        if (target) |t| {
            const gop = try dir.entries.getOrPut(g, name);
            if (gop.found_existing) {
                gop.value_ptr.*.nlink -= 1;
            } else {
                gop.key_ptr.* = g.dupe(u8, name) catch |err| {
                    _ = dir.entries.orderedRemove(name);
                    return err;
                };
            }
            gop.value_ptr.* = t;
            t.nlink += 1;
            if (t.kind == .dir) t.parent = dir;
        } else if (dir.entries.fetchOrderedRemove(name)) |kv| {
            kv.value.nlink -= 1;
            g.free(kv.key);
        }
        dir.mtime = fs.now();
        fs.journal.appendAssumeCapacity(.{ .group = group, .dir = dir, .name = jname, .target = target });
    }

    fn newGroup(fs: *Fs) u64 {
        defer fs.next_group += 1;
        return fs.next_group;
    }

    fn applyDurable(fs: *Fs, op: MetaOp) void {
        const g = fs.alloc();
        if (op.target) |t| {
            const gop = op.dir.durable.getOrPut(g, op.name) catch return;
            if (!gop.found_existing) gop.key_ptr.* = g.dupe(u8, op.name) catch {
                _ = op.dir.durable.orderedRemove(op.name);
                return;
            };
            gop.value_ptr.* = t;
        } else if (op.dir.durable.fetchOrderedRemove(op.name)) |kv| g.free(kv.key);
    }

    /// Makes journaled name changes durable: those on `dir` (strict), or all.
    fn commit(fs: *Fs, dir: ?*Node) void {
        const g = fs.alloc();
        var i: usize = 0;
        while (i < fs.journal.items.len) {
            const op = fs.journal.items[i];
            if (dir == null or op.dir == dir.?) {
                fs.applyDurable(op);
                g.free(op.name);
                _ = fs.journal.orderedRemove(i);
            } else i += 1;
        }
    }

    // ── crash ───────────────────────────────────────────────────────────────

    /// Resolves what the disk holds after a power cut, and makes it the
    /// current tree. Open handles are gone (the host's tasks are).
    pub fn crash(fs: *Fs) void {
        const g = fs.alloc();
        fs.open.clearRetainingCapacity();
        // A prefix of the journal, whole groups at a time, made it.
        var groups: u64 = 0;
        var last: u64 = 0;
        for (fs.journal.items) |op| if (op.group != last) {
            groups += 1;
            last = op.group;
        };
        const keep = fs.prng.belowWide(groups + 1);
        var seen: u64 = 0;
        last = 0;
        for (fs.journal.items) |op| {
            if (op.group != last) {
                seen += 1;
                last = op.group;
            }
            if (seen <= keep) fs.applyDurable(op);
            g.free(op.name);
        }
        fs.journal.clearRetainingCapacity();

        const o = fs.host.sim.opts.fs;
        fs.used_bytes = 0;
        for (fs.nodes.items) |n| {
            n.lock_exclusive = false;
            n.lock_shared = 0;
            if (n.kind != .file) continue;
            // Unsynced data: each sector or truncation survives on its own.
            var out = n.synced;
            n.synced = .empty;
            for (n.pending.items) |op| switch (op) {
                .write => |w| {
                    var off: u64 = 0;
                    while (off < w.bytes.len) {
                        const abs = w.off + off;
                        const to_boundary = o.sector_bytes - @as(u32, @intCast(abs % o.sector_bytes));
                        const k: usize = @intCast(@min(@as(u64, to_boundary), w.bytes.len - off));
                        if (fs.prng.permille(o.crash_keep_permille)) writeAt(g, &out, abs, w.bytes[off..][0..k]) catch {};
                        off += k;
                    }
                },
                .set_len => |len| if (fs.prng.permille(o.crash_keep_permille)) resize(g, &out, len) catch {},
            };
            freePending(g, &n.pending);
            n.data.clearRetainingCapacity();
            n.data.appendSlice(g, out.items) catch {};
            n.synced = out;
        }
        // The current tree is now what the disk says.
        for (fs.nodes.items) |n| n.nlink = 0;
        fs.root.nlink = 1;
        for (fs.nodes.items) |n| {
            if (n.kind != .dir) continue;
            Node.freeEntries(g, &n.entries);
            n.entries = .empty;
            for (n.durable.keys(), n.durable.values()) |k, v| {
                const key = g.dupe(u8, k) catch continue;
                n.entries.put(g, key, v) catch {
                    g.free(key);
                    continue;
                };
                v.nlink += 1;
                if (v.kind == .dir) v.parent = n;
            }
        }
        for (fs.nodes.items) |n| if (n.kind == .file and n.nlink > 0) {
            fs.used_bytes += n.data.items.len;
        };
    }

    fn writeAt(g: Allocator, list: *std.ArrayList(u8), off: u64, bytes: []const u8) Allocator.Error!void {
        const end: usize = @intCast(off + bytes.len);
        if (end > list.items.len) {
            const old = list.items.len;
            try list.resize(g, end);
            @memset(list.items[old..end], 0);
        }
        @memcpy(list.items[@intCast(off)..end], bytes);
    }

    fn resize(g: Allocator, list: *std.ArrayList(u8), len: u64) Allocator.Error!void {
        const n: usize = @intCast(len);
        const old = list.items.len;
        try list.resize(g, n);
        if (n > old) @memset(list.items[old..n], 0);
    }

    // ── faults ──────────────────────────────────────────────────────────────

    /// Flips one bit of one stored file, on disk and in the current view.
    pub fn bitRot(fs: *Fs) void {
        var candidates: usize = 0;
        for (fs.nodes.items) |n| if (n.kind == .file and n.nlink > 0 and n.data.items.len > 0) {
            candidates += 1;
        };
        if (candidates == 0) return;
        var pick = fs.prng.below(candidates);
        for (fs.nodes.items) |n| {
            if (n.kind != .file or n.nlink == 0 or n.data.items.len == 0) continue;
            if (pick > 0) {
                pick -= 1;
                continue;
            }
            const bit = fs.prng.below(n.data.items.len * 8);
            const mask = @as(u8, 1) << @intCast(bit % 8);
            n.data.items[bit / 8] ^= mask;
            if (bit / 8 < n.synced.items.len) n.synced.items[bit / 8] ^= mask;
            return;
        }
    }

    // ── test-side helpers ───────────────────────────────────────────────────

    /// Creates `path` (and its directories) with `data`, durable at once.
    pub fn put(fs: *Fs, path: []const u8, data: []const u8) !void {
        const g = fs.alloc();
        var cur = fs.root;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        var last: ?[]const u8 = null;
        while (it.next()) |comp| {
            if (last) |prev| {
                cur = if (cur.entries.get(prev)) |n| n else blk: {
                    const d = try fs.newNode(.dir);
                    try fs.setEntry(cur, prev, d, fs.newGroup());
                    break :blk d;
                };
                if (cur.kind != .dir) return error.NotDir;
            }
            last = comp;
        }
        const name = last orelse return error.BadPathName;
        const f = try fs.newNode(.file);
        try f.data.appendSlice(g, data);
        try f.synced.appendSlice(g, data);
        fs.used_bytes += data.len;
        try fs.setEntry(cur, name, f, fs.newGroup());
        fs.commit(null);
    }

    /// The current contents of `path`, or null.
    pub fn get(fs: *Fs, path: []const u8) ?[]const u8 {
        const r = fs.resolveFollow(.{ .handle = cwd_handle }, path) catch return null;
        const n = r.node orelse return null;
        if (n.kind != .file) return null;
        return n.data.items;
    }

    // ── the vtable's file system entries ────────────────────────────────────

    fn cancelPoint(fs: *Fs) error{Canceled}!void {
        const sim = fs.host.sim;
        if (sim.current) |me| try sim.cancelPoint(me);
    }

    fn statOf(n: *const Node) File.Stat {
        return .{
            .inode = n.ino,
            .nlink = n.nlink,
            .size = if (n.kind == .dir) 0 else n.data.items.len,
            .permissions = n.perm,
            .kind = kindOf(n),
            .atime = .{ .nanoseconds = n.atime },
            .mtime = .{ .nanoseconds = n.mtime },
            .ctime = .{ .nanoseconds = n.ctime },
            .block_size = 4096,
        };
    }

    fn kindOf(n: *const Node) File.Kind {
        return switch (n.kind) {
            .file => .file,
            .dir => .directory,
            .symlink => .sym_link,
        };
    }

    pub fn createDir(fs: *Fs, dir: Dir, path: []const u8, perm: Dir.Permissions) Dir.CreateDirError!void {
        try fs.cancelPoint();
        const r = try fs.resolve(dir, path);
        if (r.node != null) return error.PathAlreadyExists;
        const parent = r.parent orelse return error.PathAlreadyExists;
        const d = fs.newNode(.dir) catch return error.SystemResources;
        d.perm = perm;
        fs.setEntry(parent, r.name, d, fs.newGroup()) catch return error.SystemResources;
    }

    pub fn createDirPath(fs: *Fs, dir: Dir, path: []const u8, perm: Dir.Permissions) Dir.CreateDirPathError!Dir.CreatePathStatus {
        try fs.cancelPoint();
        if (path.len == 0) return error.BadPathName;
        var cur = try fs.dirNode(dir, path);
        var created = false;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        while (it.next()) |comp| {
            if (std.mem.eql(u8, comp, ".")) continue;
            if (std.mem.eql(u8, comp, "..")) {
                cur = cur.parent orelse cur;
                continue;
            }
            if (cur.entries.get(comp) != null) {
                var hops: u8 = 0;
                cur = fs.step(cur, comp, &hops) catch |err| return switch (err) {
                    error.FileNotFound => error.FileNotFound,
                    error.NotDir => error.NotDir,
                    error.SymLinkLoop => error.SymLinkLoop,
                    error.BadPathName => error.BadPathName,
                };
            } else {
                const d = fs.newNode(.dir) catch return error.SystemResources;
                d.perm = perm;
                fs.setEntry(cur, comp, d, fs.newGroup()) catch return error.SystemResources;
                cur = d;
                created = true;
            }
        }
        return if (created) .created else .existed;
    }

    pub fn openDir(fs: *Fs, dir: Dir, path: []const u8, options: Dir.OpenOptions) Dir.OpenError!Dir {
        try fs.cancelPoint();
        const r = if (options.follow_symlinks) try fs.resolveFollow(dir, path) else try fs.resolve(dir, path);
        const n = r.node orelse return error.FileNotFound;
        if (n.kind != .dir) return error.NotDir;
        const handle = fs.newHandle(.{ .node = n, .read = true, .write = false }) catch return error.SystemResources;
        return .{ .handle = handle };
    }

    pub fn createDirPathOpen(fs: *Fs, dir: Dir, path: []const u8, perm: Dir.Permissions, options: Dir.OpenOptions) Dir.CreateDirPathOpenError!Dir {
        _ = try fs.createDirPath(dir, path, perm);
        return fs.openDir(dir, path, options);
    }

    pub fn closeDirs(fs: *Fs, dirs: []const Dir) void {
        for (dirs) |d| _ = fs.open.remove(d.handle);
    }

    pub fn statDir(fs: *Fs, dir: Dir) File.StatError!File.Stat {
        const n = fs.dirNode(dir, "") catch return error.AccessDenied;
        return statOf(n);
    }

    pub fn statFile(fs: *Fs, dir: Dir, path: []const u8, follow: bool) Dir.StatFileError!File.Stat {
        try fs.cancelPoint();
        const r = if (follow) try fs.resolveFollow(dir, path) else try fs.resolve(dir, path);
        return statOf(r.node orelse return error.FileNotFound);
    }

    pub fn access(fs: *Fs, dir: Dir, path: []const u8) Dir.AccessError!void {
        try fs.cancelPoint();
        const r = fs.resolveFollow(dir, path) catch |err| switch (err) {
            error.NotDir => return error.FileNotFound,
            else => |e| return e,
        };
        if (r.node == null) return error.FileNotFound;
    }

    pub fn createFile(fs: *Fs, dir: Dir, path: []const u8, options: Dir.CreateFileOptions) File.OpenError!File {
        try fs.cancelPoint();
        const r = try fs.resolveFollow(dir, path);
        var node = r.node;
        if (node) |n| {
            if (options.exclusive) return error.PathAlreadyExists;
            if (n.kind == .dir) return error.IsDir;
            if (options.truncate and n.data.items.len > 0) fs.truncate(n, 0) catch return error.SystemResources;
        } else {
            const parent = r.parent orelse return error.IsDir;
            const n = fs.newNode(.file) catch return error.SystemResources;
            n.perm = options.permissions;
            fs.setEntry(parent, r.name, n, fs.newGroup()) catch return error.SystemResources;
            node = n;
        }
        const handle = fs.newHandle(.{ .node = node.?, .read = options.read, .write = true }) catch return error.SystemResources;
        const file: File = .{ .handle = handle, .flags = .{ .nonblocking = false } };
        if (options.lock != .none) fs.acquireLock(file, options.lock, !options.lock_nonblocking) catch |err| {
            fs.closeFiles(&.{file});
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                error.Canceled => error.Canceled,
            };
        };
        return file;
    }

    pub fn openFile(fs: *Fs, dir: Dir, path: []const u8, options: Dir.OpenFileOptions) File.OpenError!File {
        try fs.cancelPoint();
        const r = if (options.follow_symlinks) try fs.resolveFollow(dir, path) else try fs.resolve(dir, path);
        const n = r.node orelse return error.FileNotFound;
        if (n.kind == .symlink) return error.SymLinkLoop; // O_NOFOLLOW on a link: ELOOP
        if (n.kind == .dir and (!options.allow_directory or options.isWrite())) return error.IsDir;
        const handle = fs.newHandle(.{ .node = n, .read = options.isRead(), .write = options.isWrite() }) catch return error.SystemResources;
        const file: File = .{ .handle = handle, .flags = .{ .nonblocking = false } };
        if (options.lock != .none) fs.acquireLock(file, options.lock, !options.lock_nonblocking) catch |err| {
            fs.closeFiles(&.{file});
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                error.Canceled => error.Canceled,
            };
        };
        return file;
    }

    pub fn createFileAtomic(fs: *Fs, dir: Dir, path: []const u8, options: Dir.CreateFileAtomicOptions) Dir.CreateFileAtomicError!File.Atomic {
        try fs.cancelPoint();
        const dirname = std.fs.path.dirname(path);
        const parent: Dir = if (dirname) |dn| blk: {
            if (options.make_path) _ = fs.createDirPath(dir, dn, .default_dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return error.FileNotFound,
            };
            break :blk fs.openDir(dir, dn, .{}) catch |err| return switch (err) {
                error.NotDir => error.NotDir,
                error.Canceled => error.Canceled,
                else => error.FileNotFound,
            };
        } else dir;
        const hex = fs.prng.next();
        const tmp = std.fmt.hex(hex);
        const file = fs.createFile(parent, &tmp, .{ .read = true, .exclusive = true, .permissions = options.permissions }) catch |err| return switch (err) {
            error.PathAlreadyExists => error.Unexpected,
            error.IsDir => error.Unexpected,
            error.WouldBlock => error.WouldBlock,
            error.FileNotFound => error.FileNotFound,
            error.NotDir => error.NotDir,
            error.Canceled => error.Canceled,
            error.BadPathName => error.BadPathName,
            else => error.SystemResources,
        };
        return .{
            .file = file,
            .file_basename_hex = hex,
            .file_open = true,
            .file_exists = true,
            .dir = parent,
            .close_dir_on_deinit = dirname != null,
            .dest_sub_path = std.fs.path.basename(path),
        };
    }

    pub fn closeFiles(fs: *Fs, files: []const File) void {
        for (files) |f| {
            if (f.handle <= 2) continue; // stdio
            const of = fs.open.get(f.handle) orelse continue;
            fs.releaseLock(of);
            _ = fs.open.remove(f.handle);
        }
    }

    pub fn deleteFile(fs: *Fs, dir: Dir, path: []const u8) Dir.DeleteFileError!void {
        try fs.cancelPoint();
        const r = try fs.resolve(dir, path);
        const n = r.node orelse return error.FileNotFound;
        if (n.kind == .dir) return error.IsDir;
        const parent = r.parent orelse return error.IsDir;
        fs.setEntry(parent, r.name, null, fs.newGroup()) catch return error.SystemResources;
        if (n.nlink == 0 and n.kind == .file) fs.used_bytes -|= n.data.items.len;
    }

    pub fn deleteDir(fs: *Fs, dir: Dir, path: []const u8) Dir.DeleteDirError!void {
        try fs.cancelPoint();
        const r = try fs.resolve(dir, path);
        const n = r.node orelse return error.FileNotFound;
        if (n.kind != .dir) return error.NotDir;
        if (n.entries.count() > 0) return error.DirNotEmpty;
        const parent = r.parent orelse return error.FileBusy;
        fs.setEntry(parent, r.name, null, fs.newGroup()) catch return error.SystemResources;
    }

    pub fn rename(fs: *Fs, old_dir: Dir, old_path: []const u8, new_dir: Dir, new_path: []const u8, replace: bool) Dir.RenamePreserveError!void {
        try fs.cancelPoint();
        const from = try fs.resolve(old_dir, old_path);
        const n = from.node orelse return error.FileNotFound;
        const from_parent = from.parent orelse return error.FileBusy;
        const to = try fs.resolve(new_dir, new_path);
        const to_parent = to.parent orelse return error.FileBusy;
        if (to.node) |existing| {
            if (existing == n) return;
            if (!replace) return error.PathAlreadyExists;
            if (existing.kind == .dir and n.kind != .dir) return error.IsDir;
            if (existing.kind != .dir and n.kind == .dir) return error.NotDir;
            if (existing.kind == .dir and existing.entries.count() > 0) return error.DirNotEmpty;
        }
        if (n.kind == .dir) {
            // Not into its own subtree.
            var up: ?*Node = to_parent;
            while (up) |u| : (up = if (u.parent == u) null else u.parent) {
                if (u == n) return error.FileBusy;
                if (u == fs.root) break;
            }
        }
        const group = fs.newGroup();
        const replaced = to.node;
        fs.setEntry(to_parent, to.name, n, group) catch return error.SystemResources;
        fs.setEntry(from_parent, from.name, null, group) catch return error.SystemResources;
        if (replaced) |old| if (old.nlink == 0 and old.kind == .file) {
            fs.used_bytes -|= old.data.items.len;
        };
    }

    pub fn read(fs: *Fs, reader: *Dir.Reader, out: []Dir.Entry) Dir.Reader.Error!usize {
        try fs.cancelPoint();
        const n = fs.dirNode(reader.dir, "") catch return error.AccessDenied;
        if (reader.state == .reset) {
            reader.index = 0;
            reader.state = .reading;
        }
        if (reader.state == .finished) return 0;
        var count: usize = 0;
        while (count < out.len and reader.index < n.entries.count()) : (reader.index += 1) {
            const child = n.entries.values()[reader.index];
            out[count] = .{
                .name = n.entries.keys()[reader.index],
                .kind = kindOf(child),
                .inode = child.ino,
            };
            count += 1;
        }
        if (reader.index >= n.entries.count()) reader.state = .finished;
        return count;
    }

    pub fn realPath(fs: *Fs, dir: Dir, sub: ?[]const u8, out: []u8) File.RealPathError!usize {
        var n = fs.dirNode(dir, sub orelse "") catch return error.FileNotFound;
        var tail: []const u8 = "";
        if (sub) |p| {
            const r = fs.resolveFollow(dir, p) catch return error.FileNotFound;
            const target = r.node orelse return error.FileNotFound;
            if (target.kind == .dir) n = target else {
                n = r.parent orelse return error.FileNotFound;
                tail = r.name;
            }
        }
        // Walk up collecting names, then write them in order.
        var names: [64][]const u8 = undefined;
        var depth: usize = 0;
        var cur = n;
        while (cur != fs.root) {
            const p = cur.parent orelse break;
            const idx = std.mem.indexOfScalar(*Node, p.entries.values(), cur) orelse break;
            if (depth == names.len) return error.NameTooLong;
            names[depth] = p.entries.keys()[idx];
            depth += 1;
            cur = p;
        }
        var w: std.Io.Writer = .fixed(out);
        if (depth == 0 and tail.len == 0) w.writeAll("/") catch return error.NameTooLong;
        while (depth > 0) {
            depth -= 1;
            w.print("/{s}", .{names[depth]}) catch return error.NameTooLong;
        }
        if (tail.len > 0) w.print("/{s}", .{tail}) catch return error.NameTooLong;
        return w.end;
    }

    pub fn symLink(fs: *Fs, dir: Dir, target: []const u8, link_path: []const u8) Dir.SymLinkError!void {
        try fs.cancelPoint();
        if (target.len == 0) return error.FileNotFound;
        const r = try fs.resolve(dir, link_path);
        if (r.node != null) return error.PathAlreadyExists;
        const parent = r.parent orelse return error.PathAlreadyExists;
        const n = fs.newNode(.symlink) catch return error.SystemResources;
        n.perm = .default_file;
        n.data.appendSlice(fs.alloc(), target) catch return error.SystemResources;
        fs.setEntry(parent, r.name, n, fs.newGroup()) catch return error.SystemResources;
    }

    pub fn readLink(fs: *Fs, dir: Dir, path: []const u8, buf: []u8) Dir.ReadLinkError!usize {
        try fs.cancelPoint();
        const r = try fs.resolve(dir, path);
        const n = r.node orelse return error.FileNotFound;
        if (n.kind != .symlink) return error.NotLink;
        const k = @min(buf.len, n.data.items.len);
        @memcpy(buf[0..k], n.data.items[0..k]);
        return k;
    }

    /// A second name for an existing file (never a directory, as on Linux).
    pub fn hardLink(fs: *Fs, old_dir: Dir, old_path: []const u8, new_dir: Dir, new_path: []const u8, follow: bool) Dir.HardLinkError!void {
        try fs.cancelPoint();
        const from = if (follow) try fs.resolveFollow(old_dir, old_path) else try fs.resolve(old_dir, old_path);
        const n = from.node orelse return error.FileNotFound;
        return fs.linkNode(n, new_dir, new_path);
    }

    pub fn fileHardLink(fs: *Fs, file: File, new_dir: Dir, new_path: []const u8) File.HardLinkError!void {
        try fs.cancelPoint();
        const of = fs.fileOf(file) orelse return error.FileNotFound;
        return fs.linkNode(of.node, new_dir, new_path);
    }

    fn linkNode(fs: *Fs, n: *Node, new_dir: Dir, new_path: []const u8) File.HardLinkError!void {
        if (n.kind == .dir) return error.PermissionDenied;
        if (n.nlink == 0) return error.FileNotFound;
        const to = try fs.resolve(new_dir, new_path);
        if (to.node != null) return error.PathAlreadyExists;
        const parent = to.parent orelse return error.PathAlreadyExists;
        fs.setEntry(parent, to.name, n, fs.newGroup()) catch return error.SystemResources;
        n.ctime = fs.now();
    }

    /// The node a `(dir, path)` metadata call targets.
    fn metaNode(fs: *Fs, dir: Dir, path: ?[]const u8, follow: bool) ResolveError!*Node {
        const p = path orelse return fs.dirNode(dir, "");
        const r = if (follow) try fs.resolveFollow(dir, p) else try fs.resolve(dir, p);
        return r.node orelse error.FileNotFound;
    }

    pub fn setPermissions(fs: *Fs, n: *Node, perm: File.Permissions) void {
        n.perm = perm;
        n.ctime = fs.now();
    }

    pub fn setOwner(fs: *Fs, n: *Node, uid: ?File.Uid, gid: ?File.Gid) void {
        if (uid) |u| n.uid = u;
        if (gid) |g| n.gid = g;
        n.ctime = fs.now();
    }

    pub fn setTimestamps(fs: *Fs, n: *Node, atime: File.SetTimestamp, mtime: File.SetTimestamp) void {
        const t = fs.now();
        switch (atime) {
            .unchanged => {},
            .now => n.atime = t,
            .new => |ts| n.atime = ts.nanoseconds,
        }
        switch (mtime) {
            .unchanged => {},
            .now => n.mtime = t,
            .new => |ts| n.mtime = ts.nanoseconds,
        }
        n.ctime = t;
    }

    pub fn nodeAt(fs: *Fs, dir: Dir, path: ?[]const u8, follow: bool) ResolveError!*Node {
        return fs.metaNode(dir, path, follow);
    }

    pub fn nodeOfFile(fs: *Fs, file: File) ?*Node {
        const of = fs.fileOf(file) orelse return null;
        return of.node;
    }

    /// The path of an open file: its directory's path and the first name
    /// under which that directory holds it (a hard-linked file has several).
    pub fn fileRealPath(fs: *Fs, file: File, out: []u8) File.RealPathError!usize {
        const of = fs.fileOf(file) orelse return error.FileNotFound;
        const n = of.node;
        if (n.kind == .dir) return fs.realPath(.{ .handle = file.handle }, null, out);
        for (fs.nodes.items) |d| {
            if (d.kind != .dir) continue;
            const idx = std.mem.indexOfScalar(*Node, d.entries.values(), n) orelse continue;
            const name = d.entries.keys()[idx];
            const handle = fs.newHandle(.{ .node = d, .read = true, .write = false }) catch return error.SystemResources;
            defer _ = fs.open.remove(handle);
            const len = try fs.realPath(.{ .handle = handle }, null, out);
            var w: std.Io.Writer = .fixed(out[len..]);
            if (len == 1) w.writeAll(name) catch return error.NameTooLong else w.print("/{s}", .{name}) catch return error.NameTooLong;
            return len + w.end;
        }
        return error.FileNotFound; // unlinked
    }

    // files

    fn fileOf(fs: *Fs, file: File) ?*OpenFile {
        return fs.openOf(file.handle);
    }

    pub fn stat(fs: *Fs, file: File) File.StatError!File.Stat {
        const of = fs.fileOf(file) orelse return error.AccessDenied;
        return statOf(of.node);
    }

    pub fn length(fs: *Fs, file: File) File.LengthError!u64 {
        const of = fs.fileOf(file) orelse return error.AccessDenied;
        return if (of.node.kind == .file) of.node.data.items.len else 0;
    }

    pub fn readAt(fs: *Fs, file: File, data: []const []u8, offset: u64) File.ReadPositionalError!usize {
        try fs.cancelPoint();
        return fs.readAtInner(file, data, offset);
    }

    fn readAtInner(fs: *Fs, file: File, data: []const []u8, offset: u64) File.ReadPositionalError!usize {
        const of = fs.fileOf(file) orelse return error.AccessDenied;
        if (of.node.kind == .dir) return error.IsDir;
        if (!of.read) return error.NotOpenForReading;
        if (fs.fail_read > 0) {
            fs.fail_read -= 1;
            return error.InputOutput;
        }
        const n = of.node;
        n.atime = fs.now();
        if (offset >= n.data.items.len) return 0;
        var src = n.data.items[@intCast(offset)..];
        var total: usize = 0;
        for (data) |d| {
            const k = @min(d.len, src.len);
            @memcpy(d[0..k], src[0..k]);
            src = src[k..];
            total += k;
            if (src.len == 0) break;
        }
        return total;
    }

    pub fn writeAtFile(fs: *Fs, file: File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) File.WritePositionalError!usize {
        try fs.cancelPoint();
        return fs.writeAtInner(file, header, data, splat, offset);
    }

    fn writeAtInner(fs: *Fs, file: File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) File.WritePositionalError!usize {
        const of = fs.fileOf(file) orelse return error.AccessDenied;
        if (of.node.kind == .dir) return error.NotOpenForWriting;
        if (!of.write) return error.NotOpenForWriting;
        if (fs.fail_write > 0) {
            fs.fail_write -= 1;
            return error.InputOutput;
        }
        var total = header.len;
        if (data.len > 0) {
            for (data[0 .. data.len - 1]) |d| total += d.len;
            total += data[data.len - 1].len * splat;
        }
        if (total == 0) return 0;
        const n = of.node;
        const g = fs.alloc();
        // Capacity: count only the growth this write causes.
        const end = offset + total;
        const growth = end -| n.data.items.len;
        var amount = total;
        if (fs.capacity) |cap| {
            const room = cap -| fs.used_bytes;
            if (growth > room) {
                const allowed_end = n.data.items.len + room;
                if (allowed_end <= offset) return error.NoSpaceLeft;
                amount = @intCast(allowed_end - offset);
            }
        }
        const bytes = g.alloc(u8, amount) catch return error.SystemResources;
        var o: usize = 0;
        for ([_][]const u8{header}) |part| {
            const k = @min(part.len, amount - o);
            @memcpy(bytes[o..][0..k], part[0..k]);
            o += k;
        }
        if (data.len > 0) {
            for (data[0 .. data.len - 1]) |part| {
                const k = @min(part.len, amount - o);
                @memcpy(bytes[o..][0..k], part[0..k]);
                o += k;
            }
            var rep: usize = 0;
            while (rep < splat and o < amount) : (rep += 1) {
                const part = data[data.len - 1];
                const k = @min(part.len, amount - o);
                @memcpy(bytes[o..][0..k], part[0..k]);
                o += k;
            }
        }
        fs.host.sim.mixData(fs.host, bytes);
        const old_len = n.data.items.len;
        writeAt(g, &n.data, offset, bytes) catch {
            g.free(bytes);
            return error.SystemResources;
        };
        n.pending.append(g, .{ .write = .{ .off = offset, .bytes = bytes } }) catch {
            g.free(bytes);
            return error.SystemResources;
        };
        fs.used_bytes += n.data.items.len - old_len;
        n.mtime = fs.now();
        return amount;
    }

    fn truncate(fs: *Fs, n: *Node, len: u64) Allocator.Error!void {
        const g = fs.alloc();
        try n.pending.ensureUnusedCapacity(g, 1);
        const old = n.data.items.len;
        try resize(g, &n.data, len);
        n.pending.appendAssumeCapacity(.{ .set_len = len });
        if (len > old) fs.used_bytes += len - old else fs.used_bytes -|= old - len;
        n.mtime = fs.now();
    }

    pub fn setLength(fs: *Fs, file: File, len: u64) File.SetLengthError!void {
        try fs.cancelPoint();
        const of = fs.fileOf(file) orelse return error.AccessDenied;
        if (of.node.kind == .dir or !of.write) return error.AccessDenied;
        if (fs.capacity) |cap| if (len > of.node.data.items.len and len - of.node.data.items.len > cap -| fs.used_bytes)
            return error.FileTooBig;
        fs.truncate(of.node, len) catch return error.InputOutput;
    }

    pub fn sync(fs: *Fs, file: File) File.SyncError!void {
        try fs.cancelPoint();
        const of = fs.fileOf(file) orelse return error.AccessDenied;
        if (fs.fail_sync > 0) {
            fs.fail_sync -= 1;
            return error.InputOutput;
        }
        const n = of.node;
        const g = fs.alloc();
        switch (n.kind) {
            .file => {
                n.synced.clearRetainingCapacity();
                n.synced.appendSlice(g, n.data.items) catch return error.InputOutput;
                freePending(g, &n.pending);
                if (fs.host.sim.opts.fs.durability == .journal) fs.commit(null);
            },
            .dir => fs.commit(if (fs.host.sim.opts.fs.durability == .journal) null else n),
            .symlink => {}, // a link's target is durable with its name
        }
    }

    pub fn seekTo(fs: *Fs, file: File, pos: u64) File.SeekError!void {
        const of = fs.fileOf(file) orelse return error.Unseekable;
        of.pos = pos;
    }

    pub fn seekBy(fs: *Fs, file: File, delta: i64) File.SeekError!void {
        const of = fs.fileOf(file) orelse return error.Unseekable;
        const p: i128 = @as(i128, of.pos) + delta;
        if (p < 0) return error.Unseekable;
        of.pos = @intCast(p);
    }

    pub fn readStreaming(fs: *Fs, file: File, data: []const []u8) Io.Operation.FileReadStreaming.Error!usize {
        if (file.handle == 0) return error.EndOfStream; // stdin is empty
        const of = fs.fileOf(file) orelse return error.AccessDenied;
        const n = fs.readAtInner(file, data, of.pos) catch |err| return switch (err) {
            error.NotOpenForReading => error.NotOpenForReading,
            error.InputOutput => error.InputOutput,
            error.IsDir => error.IsDir,
            error.AccessDenied => error.AccessDenied,
            else => error.Unexpected,
        };
        if (n == 0) {
            var cap: usize = 0;
            for (data) |d| cap += d.len;
            if (cap > 0) return error.EndOfStream;
        }
        of.pos += n;
        return n;
    }

    pub fn writeStreaming(fs: *Fs, file: File, header: []const u8, data: []const []const u8, splat: usize) Io.Operation.FileWriteStreaming.Error!usize {
        if (file.handle == 1 or file.handle == 2) return fs.toConsole(header, data, splat);
        const of = fs.fileOf(file) orelse return error.AccessDenied;
        const n = fs.writeAtInner(file, header, data, splat, of.pos) catch |err| return switch (err) {
            error.NoSpaceLeft => error.NoSpaceLeft,
            error.InputOutput => error.InputOutput,
            error.NotOpenForWriting => error.NotOpenForWriting,
            error.AccessDenied => error.AccessDenied,
            error.SystemResources => error.SystemResources,
            else => error.Unexpected,
        };
        of.pos += n;
        return n;
    }

    fn toConsole(fs: *Fs, header: []const u8, data: []const []const u8, splat: usize) usize {
        const g = fs.alloc();
        const cap = 64 * 1024;
        var total = header.len;
        fs.console.appendSlice(g, header[0..@min(header.len, cap -| fs.console.items.len)]) catch {};
        if (data.len > 0) {
            for (data[0 .. data.len - 1]) |d| {
                total += d.len;
                fs.console.appendSlice(g, d[0..@min(d.len, cap -| fs.console.items.len)]) catch {};
            }
            for (0..splat) |_| {
                const d = data[data.len - 1];
                total += d.len;
                fs.console.appendSlice(g, d[0..@min(d.len, cap -| fs.console.items.len)]) catch {};
            }
        }
        return total;
    }

    // locks (flock semantics: per open file, released on close and crash)

    pub fn acquireLock(fs: *Fs, file: File, l: File.Lock, blocking: bool) error{ WouldBlock, Canceled }!void {
        while (true) {
            const of = fs.fileOf(file) orelse return error.WouldBlock;
            if (fs.tryAcquire(of, l)) return;
            if (!blocking) return error.WouldBlock;
            // Poll: a lock holder releases on close or crash, both visible
            // here within a millisecond of virtual time.
            const sim = fs.host.sim;
            const me = sim.running();
            try sim.cancelPoint(me);
            _ = sim.block(me, .sleep, true, sim.now + std.time.ns_per_ms) catch {};
            if (me.wake_reason == .canceled) {
                me.acknowledgeCancel();
                return error.Canceled;
            }
        }
    }

    fn tryAcquire(fs: *Fs, of: *OpenFile, l: File.Lock) bool {
        _ = fs;
        const n = of.node;
        fsReleaseLock(of);
        switch (l) {
            .none => return true,
            .shared => {
                if (n.lock_exclusive) return false;
                n.lock_shared += 1;
            },
            .exclusive => {
                if (n.lock_exclusive or n.lock_shared > 0) return false;
                n.lock_exclusive = true;
            },
        }
        of.lock = l;
        return true;
    }

    fn releaseLock(fs: *Fs, of: OpenFile) void {
        _ = fs;
        var copy = of;
        fsReleaseLock(&copy);
    }

    fn fsReleaseLock(of: *OpenFile) void {
        switch (of.lock) {
            .none => {},
            .shared => of.node.lock_shared -= 1,
            .exclusive => of.node.lock_exclusive = false,
        }
        of.lock = .none;
    }

    pub fn unlock(fs: *Fs, file: File) void {
        const of = fs.fileOf(file) orelse return;
        fsReleaseLock(of);
    }

    pub fn downgrade(fs: *Fs, file: File) void {
        const of = fs.fileOf(file) orelse return;
        if (of.lock != .exclusive) return;
        of.node.lock_exclusive = false;
        of.node.lock_shared += 1;
        of.lock = .shared;
    }
};
