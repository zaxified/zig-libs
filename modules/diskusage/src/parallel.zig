// SPDX-License-Identifier: MIT
//! Parallel traversal: the same `du` question as `scan.scanAt`'s sequential
//! walk, answered by `Options.threads` workers sharing one work stack.
//! Selected by `scanAt` when `threads != 1`; not a separate public entry.
//!
//! ## Shape
//!
//! One `Node` per directory. A directory is scanned by exactly one worker:
//! it lists the directory, `lstat`s every entry against the open directory
//! fd (as the sequential walk does), accumulates the non-directory entries
//! locally, and pushes every subdirectory it wants entered onto a shared
//! LIFO stack as a `Node` of its own. Workers pop nodes, open them relative
//! to the still-open parent (`O_NOFOLLOW`, then the same `(dev, ino)`
//! identity check as the sequential walk), and scan them in turn.
//!
//! ## Why the result equals the sequential one
//!
//! * Every entry is counted by exactly one scan, under the same rules
//!   (one-filesystem boundary, hard-link set, prune predicate), so the
//!   counters and the totals are sums of the same terms in another order.
//!   Every sum saturates and saturation is commutative and associative for
//!   unsigned addition, so the order cannot change even a saturated result.
//! * The hard-link set is ONE set behind the run's mutex, so a multiply
//!   linked file is counted by exactly one of its links whichever worker
//!   sees it first. Which link that is can differ from the sequential walk
//!   (and between runs) — the totals do not, the per-directory attribution
//!   of such a file does. GNU `du` has the same order dependence.
//! * A directory finishes when its own scan is done AND every child it
//!   pushed has finished (`pending`). The last one to finish reports the
//!   directory and folds its subtotal into the parent, iteratively, so the
//!   children-before-parent, root-last contract of `DirSink` holds. Order
//!   among siblings is unspecified.
//!
//! ## Bounds
//!
//! * Concurrency: `threads` workers in total, the calling thread being one.
//!   (`std.Io` may run fewer — `Io.async` runs a task inline when it has no
//!   free thread — which only makes the run slower, never different.)
//! * Memory: the stack is LIFO, so it holds the not yet started
//!   subdirectories of the directories on the workers' current paths — the
//!   widest listings, not the whole tree; each queued node is a name and
//!   (only when a callback can read it) a path copy. A directory fd stays
//!   open until its last child has been opened, so open descriptors are also
//!   bounded by the depth of the active paths, as in the sequential walk.
//! * Every callback (`on_directory`, `on_error`, `should_descend`) runs under
//!   the run's mutex: never concurrently, so a caller's sink needs no lock of
//!   its own — and must not call back into the scan.
//!
//! ## Failure and cleanup
//!
//! Only out-of-memory and `error.SinkFailed` are fatal after the root has
//! been opened. The first one sets `aborted`; every worker then stops
//! scanning, but keeps popping the stack in "discard" mode, so each node's
//! bookkeeping still completes: every fd is closed, every allocation freed
//! and no task outlives `walk`. Callbacks stop being called once aborted.

const std = @import("std");
const stat = @import("stat.zig");
const scan = @import("scan.zig");

const Allocator = std.mem.Allocator;
const Totals = scan.Totals;
const Report = scan.Report;
const Options = scan.Options;

/// Test-visible measurements of one run.
pub const Stats = struct {
    /// Most workers ever inside a scan at the same moment.
    peak_active: usize = 0,
};

const Fatal = error{ OutOfMemory, SinkFailed };

const Node = struct {
    parent: ?*Node,
    /// Path relative to the scan root; empty unless a callback can read it.
    path: []const u8,
    /// NUL-terminated basename, needed only until the directory is opened.
    name: ?[:0]const u8,
    /// `(dev, ino)` of the directory as `lstat`'ed by its parent; what the
    /// opened fd must turn out to be.
    st_id: stat.Id,
    depth: u32,
    totals: Totals,
    /// The scan of this directory (1 while it is running) plus the children
    /// pushed and not yet finished. At 0 the directory is complete.
    pending: usize = 1,
    /// The scan (1) plus the children not yet opened: the open fd is needed
    /// until this reaches 0.
    dir_refs: usize = 1,
    dir: ?std.Io.Dir = null,
    owns_dir: bool = true,
};

const Run = struct {
    gpa: Allocator,
    io: std.Io,
    backend: stat.Backend,
    options: Options,
    root_device: u64,
    track_paths: bool,
    threads: usize,
    stats: ?*Stats,

    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    // Everything below is guarded by `mutex`, except `aborted`.
    stack: std.ArrayList(*Node) = .empty,
    active: usize = 0,
    links: std.AutoHashMapUnmanaged(stat.Id, void) = .empty,
    report: Report = .{},
    root_totals: Totals = .{},
    failure: ?Fatal = null,
    aborted: std.atomic.Value(bool) = .init(false),

    fn lock(run: *Run) void {
        run.mutex.lockUncancelable(run.io);
    }

    fn unlock(run: *Run) void {
        run.mutex.unlock(run.io);
    }

    fn failLocked(run: *Run, err: Fatal) void {
        if (run.failure == null) run.failure = err;
        run.aborted.store(true, .release);
    }

    fn fail(run: *Run, err: Fatal) void {
        run.lock();
        defer run.unlock();
        run.failLocked(err);
    }

    fn isAborted(run: *Run) bool {
        return run.aborted.load(.acquire);
    }

    /// `on_error`, mutex held.
    fn emitErrorLocked(run: *Run, path: []const u8, err: anyerror) void {
        if (run.isAborted()) return;
        if (run.options.on_error) |s| s.func(s.context, path, err);
    }

    fn emitError(run: *Run, path: []const u8, err: anyerror) void {
        run.lock();
        defer run.unlock();
        run.emitErrorLocked(path, err);
    }

    /// `on_directory`, mutex held. A failing sink aborts the run.
    fn emitDirLocked(run: *Run, path: []const u8, depth: u32, totals: Totals) void {
        if (run.isAborted()) return;
        if (run.options.on_directory) |s| s.func(s.context, path, depth, totals) catch |e| switch (e) {
            error.SinkFailed => run.failLocked(error.SinkFailed),
        };
    }

    /// The directory's fd is no longer needed by one holder; close it after
    /// the last. Mutex held.
    fn releaseDirLocked(run: *Run, n: *Node) void {
        n.dir_refs -= 1;
        if (n.dir_refs == 0 and n.owns_dir) {
            if (n.dir) |d| d.close(run.io);
            n.dir = null;
        }
    }

    fn destroyNode(run: *Run, n: *Node) void {
        std.debug.assert(n.dir_refs == 0);
        run.gpa.free(n.path);
        if (n.name) |nm| run.gpa.free(nm);
        run.gpa.destroy(n);
    }

    /// `n.pending` has reached 0: report the directory and fold it into its
    /// parent, then the parent if that was its last child, and so on up.
    /// Iterative, so the depth of the tree costs no stack. Mutex held.
    fn completeLocked(run: *Run, start: *Node) void {
        var n = start;
        while (true) {
            run.emitDirLocked(n.path, n.depth, n.totals);
            const parent = n.parent;
            const t = n.totals;
            run.destroyNode(n);
            if (parent) |p| {
                p.totals.add(t);
                p.pending -= 1;
                if (p.pending == 0) {
                    n = p;
                    continue;
                }
            } else run.root_totals = t;
            return;
        }
    }
};

fn mergeCounters(dst: *Report, src: Report) void {
    inline for (std.meta.fields(Report)) |f| {
        if (comptime !std.mem.eql(u8, f.name, "total")) {
            @field(dst, f.name) +|= @field(src, f.name);
        }
    }
}

/// Run the parallel walk of the already opened, already stat'ed root
/// directory. Does not close `root`. `options.threads` may be 0 (one worker
/// per logical CPU) or any count; 1 also works and runs on the caller alone.
pub fn walk(
    gpa: Allocator,
    io: std.Io,
    root: std.Io.Dir,
    root_stat: stat.FileStat,
    backend: stat.Backend,
    options: Options,
    stats: ?*Stats,
) scan.ScanError!Report {
    const threads: usize = if (options.threads == 0)
        (std.Thread.getCpuCount() catch 1)
    else
        options.threads;

    var r: Run = .{
        .gpa = gpa,
        .io = io,
        .backend = backend,
        .options = options,
        .root_device = root_stat.device(),
        .track_paths = options.on_directory != null or options.on_error != null or
            options.should_descend != null,
        .threads = threads,
        .stats = stats,
    };
    defer r.stack.deinit(gpa);
    defer r.links.deinit(gpa);

    const root_node = try gpa.create(Node);
    var root_totals: Totals = .{};
    root_totals.addEntry(root_stat);
    root_node.* = .{
        .parent = null,
        .path = &.{},
        .name = null,
        .st_id = root_stat.id(),
        .depth = 0,
        .totals = root_totals,
        .dir = root,
        .owns_dir = false,
    };
    scan.classify(&r.report, root_stat);

    // The root listing is done by the caller alone: it is what fills the
    // stack the workers then drain.
    scanNode(&r, root_node);

    var group: std.Io.Group = .init;
    var i: usize = 1;
    while (i < threads) : (i += 1) group.async(io, worker, .{&r});
    worker(&r);
    // Nothing cancels this call from inside; a cancelation of the caller is
    // reported after every worker has finished, so nothing is left behind.
    var canceled = false;
    group.await(io) catch {
        canceled = true;
    };

    if (r.failure) |f| return f;
    if (canceled) return error.Canceled;
    r.report.total = r.root_totals;
    return r.report;
}

fn worker(r: *Run) void {
    while (true) {
        const node = nextNode(r) orelse return;
        processNode(r, node);
        r.lock();
        r.active -= 1;
        // The last worker to go idle wakes the others so they can leave.
        if (r.active == 0 and r.stack.items.len == 0) r.cond.broadcast(r.io);
        r.unlock();
    }
}

fn nextNode(r: *Run) ?*Node {
    r.lock();
    defer r.unlock();
    while (true) {
        if (r.stack.pop()) |n| {
            r.active += 1;
            if (r.stats) |s| s.peak_active = @max(s.peak_active, r.active);
            return n;
        }
        if (r.active == 0) return null;
        r.cond.waitUncancelable(r.io, &r.mutex);
    }
}

/// Open a queued directory and scan it, or — once the run has aborted —
/// settle its bookkeeping without touching the filesystem.
fn processNode(r: *Run, node: *Node) void {
    const parent = node.parent.?;
    if (r.isAborted()) {
        r.lock();
        defer r.unlock();
        r.releaseDirLocked(parent);
        r.releaseDirLocked(node); // its own scan will never run
        r.gpa.free(node.name.?);
        node.name = null;
        node.pending = 0;
        r.completeLocked(node);
        return;
    }

    // `parent.dir` stays open at least until this node releases its
    // reference below, and was published to us through the stack's mutex.
    const opened = parent.dir.?.openDir(r.io, node.name.?, .{
        .iterate = true,
        .follow_symlinks = false,
    });
    r.gpa.free(node.name.?);
    node.name = null;

    var failure: ?anyerror = null;
    if (opened) |d| {
        // The same identity re-check as the sequential walk. With
        // `follow_symlinks = false` the open already refuses a swapped-in
        // symlink; this also catches a swapped-in directory.
        if (scan.openedAsExpected(r.backend, d.handle, node.st_id)) {
            node.dir = d;
        } else {
            d.close(r.io);
            failure = error.DirectoryChanged;
        }
    } else |err| failure = err;

    r.lock();
    r.releaseDirLocked(parent);
    if (failure) |err| {
        // An unreadable directory is counted, reported, and still holds its
        // own size — exactly what the sequential walk does.
        r.report.errors +|= 1;
        r.emitErrorLocked(node.path, err);
        r.releaseDirLocked(node); // its own scan will never run
        node.pending = 0;
        r.completeLocked(node);
        r.unlock();
        return;
    }
    r.unlock();

    scanNode(r, node);
}

/// List one directory: count what can be counted here, push what has to be
/// entered. Never fails: fatal conditions set `aborted` and end the scan.
fn scanNode(r: *Run, node: *Node) void {
    const gpa = r.gpa;
    const dir = node.dir.?;
    var local: Report = .{};
    var mine: Totals = .{};
    var path_buf: std.ArrayList(u8) = .empty;
    defer path_buf.deinit(gpa);

    // A child was opened a moment ago; the root is the caller's handle, whose
    // cursor may have been used, so it is rewound.
    var it = if (node.parent == null) dir.iterate() else dir.iterateAssumeFirstIteration();
    scanning: while (!r.isAborted()) {
        const entry = it.next(r.io) catch |err| {
            local.errors +|= 1;
            r.emitError(node.path, err);
            break;
        } orelse break;

        var name_buf: [std.Io.Dir.max_name_bytes + 1]u8 = undefined;
        if (entry.name.len >= name_buf.len) {
            local.errors +|= 1;
            r.emitError(node.path, error.NameTooLong);
            continue;
        }
        @memcpy(name_buf[0..entry.name.len], entry.name);
        name_buf[entry.name.len] = 0;
        const name_z: [:0]const u8 = name_buf[0..entry.name.len :0];

        // The entry's root-relative path, only when something can read it.
        var path: []const u8 = "";
        if (r.track_paths) {
            path_buf.clearRetainingCapacity();
            const ok = blk: {
                if (node.path.len != 0) {
                    path_buf.appendSlice(gpa, node.path) catch break :blk false;
                    path_buf.append(gpa, '/') catch break :blk false;
                }
                path_buf.appendSlice(gpa, entry.name) catch break :blk false;
                break :blk true;
            };
            if (!ok) {
                r.fail(error.OutOfMemory);
                break :scanning;
            }
            path = path_buf.items;
        }

        const st = stat.lstatAt(r.backend, dir.handle, name_z) catch |err| {
            local.errors +|= 1;
            r.emitError(path, err);
            continue;
        };

        if (r.options.one_file_system and st.device() != r.root_device) {
            local.other_filesystems_skipped +|= 1;
            continue;
        }

        if (!r.options.count_hard_links and !st.isDir() and st.nlink > 1) {
            r.lock();
            var dup = false;
            var oom = false;
            if (r.links.getOrPut(gpa, st.id())) |gop| {
                dup = gop.found_existing;
            } else |_| {
                oom = true;
                r.failLocked(error.OutOfMemory);
            }
            r.unlock();
            if (oom) break :scanning;
            if (dup) {
                local.hard_links_skipped +|= 1;
                local.hard_link_bytes_skipped +|= st.allocatedBytes();
                continue;
            }
        }

        if (!st.isDir()) {
            scan.classify(&local, st);
            mine.addEntry(st);
            continue;
        }

        // The prune predicate: asked before the directory is opened, so an
        // excluded subtree costs nothing beyond this directory's own lstat.
        const depth = node.depth + 1;
        var action: scan.Descend = .yes;
        if (r.options.should_descend) |f| {
            r.lock();
            action = if (r.isAborted()) .yes else f.func(f.context, path, depth);
            r.unlock();
        }
        if (action == .exclude) {
            local.directories_pruned +|= 1;
            continue;
        }

        scan.classify(&local, st);
        var sub: Totals = .{};
        sub.addEntry(st);

        if (action == .skip) {
            local.directories_pruned +|= 1;
            r.lock();
            r.emitDirLocked(path, depth, sub);
            r.unlock();
            mine.add(sub);
            continue;
        }

        // Queue the directory. Its name and path are owned copies: the
        // listing buffer moves on with the next entry.
        const child = gpa.create(Node) catch {
            r.fail(error.OutOfMemory);
            break :scanning;
        };
        const name_copy = gpa.dupeZ(u8, entry.name) catch {
            gpa.destroy(child);
            r.fail(error.OutOfMemory);
            break :scanning;
        };
        const path_copy: []const u8 = if (r.track_paths) gpa.dupe(u8, path) catch {
            gpa.free(name_copy);
            gpa.destroy(child);
            r.fail(error.OutOfMemory);
            break :scanning;
        } else &.{};
        child.* = .{
            .parent = node,
            .path = path_copy,
            .name = name_copy,
            .st_id = st.id(),
            .depth = depth,
            .totals = sub,
        };
        r.lock();
        r.stack.append(gpa, child) catch {
            r.failLocked(error.OutOfMemory);
            r.unlock();
            gpa.free(name_copy);
            gpa.free(path_copy);
            gpa.destroy(child);
            break :scanning;
        };
        node.pending += 1;
        node.dir_refs += 1;
        r.cond.signal(r.io);
        r.unlock();
    }

    r.lock();
    defer r.unlock();
    mergeCounters(&r.report, local);
    node.totals.add(mine);
    r.releaseDirLocked(node);
    node.pending -= 1;
    if (node.pending == 0) r.completeLocked(node);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const linux = std.os.linux;

fn testIo(threaded: *std.Io.Threaded) std.Io {
    return threaded.io();
}

const Entry = struct { path: []u8, depth: u32, totals: Totals };

/// Records every directory subtotal. The parallel walk calls sinks one at a
/// time, so no lock is needed here — which the tests below rely on.
const Collect = struct {
    gpa: Allocator,
    entries: std.ArrayList(Entry) = .empty,
    errors: std.ArrayList([]u8) = .empty,
    descend_calls: usize = 0,
    /// Directory paths the predicate answers `.skip` / `.exclude` for.
    skip_path: ?[]const u8 = null,
    exclude_path: ?[]const u8 = null,
    /// Set if the predicate ever saw a path inside a pruned directory.
    saw_inside_pruned: bool = false,

    fn deinit(self: *Collect) void {
        for (self.entries.items) |e| self.gpa.free(e.path);
        self.entries.deinit(self.gpa);
        for (self.errors.items) |e| self.gpa.free(e);
        self.errors.deinit(self.gpa);
    }

    fn onDirectory(ctx: ?*anyopaque, path: []const u8, depth: u32, totals: Totals) scan.SinkError!void {
        const self: *Collect = @ptrCast(@alignCast(ctx.?));
        const owned = self.gpa.dupe(u8, path) catch return error.SinkFailed;
        self.entries.append(self.gpa, .{ .path = owned, .depth = depth, .totals = totals }) catch {
            self.gpa.free(owned);
            return error.SinkFailed;
        };
    }

    fn onError(ctx: ?*anyopaque, path: []const u8, _: anyerror) void {
        const self: *Collect = @ptrCast(@alignCast(ctx.?));
        const owned = self.gpa.dupe(u8, path) catch return;
        self.errors.append(self.gpa, owned) catch self.gpa.free(owned);
    }

    fn shouldDescend(ctx: ?*anyopaque, path: []const u8, depth: u32) scan.Descend {
        const self: *Collect = @ptrCast(@alignCast(ctx.?));
        self.descend_calls += 1;
        std.debug.assert(depth >= 1);
        for ([_]?[]const u8{ self.skip_path, self.exclude_path }) |p| {
            if (p) |pp| {
                if (path.len > pp.len and std.mem.startsWith(u8, path, pp) and path[pp.len] == '/')
                    self.saw_inside_pruned = true;
            }
        }
        if (self.skip_path) |p| if (std.mem.eql(u8, path, p)) return .skip;
        if (self.exclude_path) |p| if (std.mem.eql(u8, path, p)) return .exclude;
        return .yes;
    }

    fn find(self: *const Collect, path: []const u8) ?Totals {
        for (self.entries.items) |e| if (std.mem.eql(u8, e.path, path)) return e.totals;
        return null;
    }

    fn lessThan(_: void, a: Entry, b: Entry) bool {
        return std.mem.lessThan(u8, a.path, b.path);
    }

    fn sort(self: *Collect) void {
        std.mem.sort(Entry, self.entries.items, {}, lessThan);
    }
};

/// Scan with `Collect` wired in as every callback.
fn scanCollect(gpa: Allocator, io: std.Io, dir: std.Io.Dir, sink: *Collect, threads: u32) !Report {
    return scan.scanAt(gpa, io, dir, ".", .{
        .threads = threads,
        .on_directory = .{ .context = sink, .func = Collect.onDirectory },
        .on_error = .{ .context = sink, .func = Collect.onError },
        .should_descend = .{ .context = sink, .func = Collect.shouldDescend },
    });
}

/// A generated tree: random directories, a deep chain, a wide directory,
/// files of random size, symlinks, and hard links either inside one
/// directory (`cross_links = false`, so per-directory subtotals do not depend
/// on which link a run counts) or across directories.
fn buildTree(gpa: Allocator, io: std.Io, d: std.Io.Dir, seed: u64, cross_links: bool) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    var dirs: std.ArrayList([]u8) = .empty;
    defer {
        for (dirs.items) |p| gpa.free(p);
        dirs.deinit(gpa);
    }
    try dirs.append(gpa, try gpa.dupe(u8, "."));

    var i: usize = 0;
    while (i < 50) : (i += 1) {
        const parent = dirs.items[rnd.uintLessThan(usize, dirs.items.len)];
        const p = try std.fmt.allocPrint(gpa, "{s}/d{d}", .{ parent, i });
        errdefer gpa.free(p);
        try d.createDirPath(io, p);
        try dirs.append(gpa, p);
    }

    // Deep: a 25-level chain with one file at the bottom.
    {
        var chain: std.ArrayList(u8) = .empty;
        defer chain.deinit(gpa);
        try chain.appendSlice(gpa, "deep");
        var lvl: usize = 0;
        while (lvl < 25) : (lvl += 1) try chain.appendSlice(gpa, "/x");
        try d.createDirPath(io, chain.items);
        try chain.appendSlice(gpa, "/bottom.bin");
        try d.writeFile(io, .{ .sub_path = chain.items, .data = "deep" ** 100 });
    }

    // Wide: 100 sibling directories, each holding one file.
    try d.createDirPath(io, "wide");
    i = 0;
    while (i < 100) : (i += 1) {
        var buf: [64]u8 = undefined;
        const sub = try std.fmt.bufPrint(&buf, "wide/w{d}", .{i});
        try d.createDirPath(io, sub);
        var fbuf: [96]u8 = undefined;
        const f = try std.fmt.bufPrint(&fbuf, "{s}/f.bin", .{sub});
        try d.writeFile(io, .{ .sub_path = f, .data = "w" ** 300 });
    }

    // Files, with a few hard links and symlinks.
    var files: std.ArrayList([]u8) = .empty;
    defer {
        for (files.items) |p| gpa.free(p);
        files.deinit(gpa);
    }
    i = 0;
    while (i < 120) : (i += 1) {
        const parent = dirs.items[rnd.uintLessThan(usize, dirs.items.len)];
        const p = try std.fmt.allocPrint(gpa, "{s}/f{d}", .{ parent, i });
        errdefer gpa.free(p);
        const len = rnd.uintLessThan(usize, 9000);
        const data = try gpa.alloc(u8, len);
        defer gpa.free(data);
        @memset(data, 'z');
        try d.writeFile(io, .{ .sub_path = p, .data = data });
        try files.append(gpa, p);
    }
    i = 0;
    while (i < 15) : (i += 1) {
        const src = files.items[rnd.uintLessThan(usize, files.items.len)];
        const dst_dir = if (cross_links)
            dirs.items[rnd.uintLessThan(usize, dirs.items.len)]
        else
            std.fs.path.dirname(src).?;
        const dst = try std.fmt.allocPrint(gpa, "{s}/link{d}", .{ dst_dir, i });
        defer gpa.free(dst);
        try d.hardLink(src, d, dst, io, .{});
    }
    i = 0;
    while (i < 10) : (i += 1) {
        const parent = dirs.items[rnd.uintLessThan(usize, dirs.items.len)];
        const p = try std.fmt.allocPrint(gpa, "{s}/sym{d}", .{ parent, i });
        defer gpa.free(p);
        try d.symLink(io, "..", p, .{}); // a cycle if it were ever followed
    }
}

fn expectSameDirs(want: *Collect, got: *Collect) !void {
    want.sort();
    got.sort();
    try testing.expectEqual(want.entries.items.len, got.entries.items.len);
    for (want.entries.items, got.entries.items) |w, g| {
        try testing.expectEqualStrings(w.path, g.path);
        try testing.expectEqual(w.depth, g.depth);
        try testing.expectEqual(w.totals, g.totals);
    }
}

/// Children before parents, the root last, every directory exactly once.
fn expectPostOrder(c: *const Collect) !void {
    try testing.expect(c.entries.items.len > 0);
    const last = c.entries.items[c.entries.items.len - 1];
    try testing.expectEqualStrings("", last.path);
    var seen: std.StringHashMapUnmanaged(usize) = .empty;
    defer seen.deinit(testing.allocator);
    for (c.entries.items, 0..) |e, idx| {
        const gop = try seen.getOrPut(testing.allocator, e.path);
        try testing.expect(!gop.found_existing);
        gop.value_ptr.* = idx;
    }
    for (c.entries.items, 0..) |e, idx| {
        if (e.path.len == 0) continue;
        const parent_rel = std.fs.path.dirname(e.path) orelse "";
        try testing.expect(seen.get(parent_rel).? > idx);
    }
}

const test_threads = [_]u32{ 2, 3, 8, 0 };

test "parallel == sequential: totals, counters and per-directory subtotals" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .limited(8) });
    defer threaded.deinit();
    const io = testIo(&threaded);

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try buildTree(testing.allocator, io, tmp.dir, 1, false);

    var want: Collect = .{ .gpa = testing.allocator };
    defer want.deinit();
    const seq = try scanCollect(testing.allocator, io, tmp.dir, &want, 1);
    try testing.expect(seq.hard_links_skipped > 0);
    try testing.expect(seq.total.entries > 300);
    try testing.expect(seq.symlinks == 10);

    for (test_threads) |n| {
        var got: Collect = .{ .gpa = testing.allocator };
        defer got.deinit();
        const par = try scanCollect(testing.allocator, io, tmp.dir, &got, n);
        try testing.expectEqual(seq, par);
        try expectPostOrder(&got);
        try expectSameDirs(&want, &got);
        // `should_descend` was asked exactly once per directory below the root.
        try testing.expectEqual(want.descend_calls, got.descend_calls);
    }
}

test "parallel == sequential with hard links across directories: one link counted" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .limited(8) });
    defer threaded.deinit();
    const io = testIo(&threaded);

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try buildTree(testing.allocator, io, tmp.dir, 2, true);

    var want: Collect = .{ .gpa = testing.allocator };
    defer want.deinit();
    const seq = try scanCollect(testing.allocator, io, tmp.dir, &want, 1);
    try testing.expect(seq.hard_links_skipped > 0);
    // Against the count-every-link run the difference is exactly the skipped
    // links, in every mode.
    const every = try scan.scanAt(testing.allocator, io, tmp.dir, ".", .{ .count_hard_links = true, .threads = 1 });

    for ([_]u32{ 1, 2, 3, 8, 0 }) |n| {
        var got: Collect = .{ .gpa = testing.allocator };
        defer got.deinit();
        const par = try scanCollect(testing.allocator, io, tmp.dir, &got, n);
        // Which directory a shared file is attributed to may differ; the
        // report may not.
        try testing.expectEqual(seq, par);
        try expectPostOrder(&got);
        try testing.expectEqual(want.entries.items.len, got.entries.items.len);
        const par_every = try scan.scanAt(testing.allocator, io, tmp.dir, ".", .{ .count_hard_links = true, .threads = n });
        try testing.expectEqual(every, par_every);
        try testing.expectEqual(par.hard_links_skipped, par_every.total.entries - par.total.entries);
    }
}

test "parallel: an unreadable directory is reported once and stepped over" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .limited(4) });
    defer threaded.deinit();
    const io = testIo(&threaded);

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const d = tmp.dir;
    try buildTree(testing.allocator, io, d, 3, false);
    try d.createDirPath(io, "wide/locked");
    try d.writeFile(io, .{ .sub_path = "wide/locked/secret", .data = "s" ** 9000 });
    if (linux.errno(linux.fchmodat(d.handle, "wide/locked", 0o000)) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.fchmodat(d.handle, "wide/locked", 0o755);
    if (d.openDir(io, "wide/locked", .{ .iterate = true })) |*probe| {
        @constCast(probe).close(io);
        return error.SkipZigTest; // running as root defeats the premise
    } else |_| {}

    var want: Collect = .{ .gpa = testing.allocator };
    defer want.deinit();
    const seq = try scanCollect(testing.allocator, io, d, &want, 1);
    try testing.expectEqual(@as(u64, 1), seq.errors);

    for (test_threads) |n| {
        var got: Collect = .{ .gpa = testing.allocator };
        defer got.deinit();
        const par = try scanCollect(testing.allocator, io, d, &got, n);
        try testing.expectEqual(seq, par);
        try testing.expectEqual(@as(usize, 1), got.errors.items.len);
        try testing.expectEqualStrings("wide/locked", got.errors.items[0]);
        try expectSameDirs(&want, &got);
        // Counted for its own size, not descended.
        try testing.expectEqual(@as(u64, 1), got.find("wide/locked").?.entries);
    }
}

test "should_descend: a pruned subtree is never entered, sequential and parallel" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .limited(4) });
    defer threaded.deinit();
    const io = testIo(&threaded);

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const d = tmp.dir;
    try d.createDirPath(io, "keep/inner");
    try d.writeFile(io, .{ .sub_path = "keep/inner/k.bin", .data = "k" ** 700 });
    try d.createDirPath(io, "excl/inner/deeper");
    try d.writeFile(io, .{ .sub_path = "excl/e.bin", .data = "e" ** 5000 });
    try d.writeFile(io, .{ .sub_path = "excl/inner/deeper/e2.bin", .data = "e" ** 5000 });

    // The subtree's own numbers, from a scan rooted at it.
    const sub = try scan.scanAt(testing.allocator, io, d, "excl", .{});
    const full = try scan.scanAt(testing.allocator, io, d, ".", .{});
    try testing.expectEqual(@as(u64, 3), sub.directories); // excl, inner, deeper

    for ([_]u32{ 1, 2, 4 }) |n| {
        // .skip: the directory stays as one entry, its contents are unseen.
        {
            var c: Collect = .{ .gpa = testing.allocator, .skip_path = "excl" };
            defer c.deinit();
            const r = try scanCollect(testing.allocator, io, d, &c, n);
            try testing.expect(!c.saw_inside_pruned); // never asked about "excl/inner"
            try testing.expectEqual(@as(u64, 1), r.directories_pruned);
            try testing.expectEqual(full.total.entries - sub.total.entries + 1, r.total.entries);
            try testing.expectEqual(full.directories - sub.directories + 1, r.directories);
            try testing.expectEqual(@as(u64, 1), r.regular_files); // only keep/inner/k.bin
            try testing.expectEqual(@as(u64, 1), c.find("excl").?.entries);
            try testing.expect(c.find("excl/inner") == null);
            try expectPostOrder(&c);
        }
        // .exclude: as if it did not exist.
        {
            var c: Collect = .{ .gpa = testing.allocator, .exclude_path = "excl" };
            defer c.deinit();
            const r = try scanCollect(testing.allocator, io, d, &c, n);
            try testing.expect(!c.saw_inside_pruned);
            try testing.expectEqual(@as(u64, 1), r.directories_pruned);
            try testing.expectEqual(full.total.entries - sub.total.entries, r.total.entries);
            try testing.expectEqual(full.total.apparent_bytes - sub.total.apparent_bytes, r.total.apparent_bytes);
            try testing.expectEqual(full.total.allocated_bytes - sub.total.allocated_bytes, r.total.allocated_bytes);
            try testing.expect(c.find("excl") == null);
            try expectPostOrder(&c);
        }
        // A predicate that never prunes changes nothing.
        {
            var c: Collect = .{ .gpa = testing.allocator };
            defer c.deinit();
            const r = try scanCollect(testing.allocator, io, d, &c, n);
            try testing.expectEqual(full, r);
        }
    }
}

test "should_descend: a subtree that would fail if visited is not visited" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .limited(4) });
    defer threaded.deinit();
    const io = testIo(&threaded);

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const d = tmp.dir;
    try d.createDirPath(io, "ok");
    try d.createDirPath(io, "trap/locked");
    if (linux.errno(linux.fchmodat(d.handle, "trap", 0o000)) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.fchmodat(d.handle, "trap", 0o755);
    if (d.openDir(io, "trap", .{ .iterate = true })) |*probe| {
        @constCast(probe).close(io);
        return error.SkipZigTest;
    } else |_| {}

    for ([_]u32{ 1, 3 }) |n| {
        var visited: Collect = .{ .gpa = testing.allocator };
        defer visited.deinit();
        const r0 = try scanCollect(testing.allocator, io, d, &visited, n);
        try testing.expectEqual(@as(u64, 1), r0.errors); // opening `trap` fails

        var pruned: Collect = .{ .gpa = testing.allocator, .exclude_path = "trap" };
        defer pruned.deinit();
        const r1 = try scanCollect(testing.allocator, io, d, &pruned, n);
        try testing.expectEqual(@as(u64, 0), r1.errors); // never opened
        try testing.expectEqual(@as(usize, 0), pruned.errors.items.len);
    }
}

test "walk: never more workers inside a scan than options.threads" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .limited(16) });
    defer threaded.deinit();
    const io = testIo(&threaded);

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try buildTree(testing.allocator, io, tmp.dir, 4, true);

    const backend = stat.detect();
    const root_stat = try stat.lstatAt(backend, tmp.dir.handle, ".");
    var root = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer root.close(io);

    for ([_]u32{ 1, 2, 5 }) |n| {
        var stats: Stats = .{};
        const r = try walk(testing.allocator, io, root, root_stat, backend, .{ .threads = n }, &stats);
        try testing.expect(stats.peak_active >= 1);
        try testing.expect(stats.peak_active <= n);
        try testing.expect(r.total.entries > 300);
    }
}

test "a failing DirSink aborts a parallel scan cleanly: no leak, no hang" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .limited(4) });
    defer threaded.deinit();
    const io = testIo(&threaded);

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try buildTree(testing.allocator, io, tmp.dir, 5, false);

    const Failing = struct {
        calls: usize = 0,
        fn f(ctx: ?*anyopaque, _: []const u8, _: u32, _: Totals) scan.SinkError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            if (self.calls >= 3) return error.SinkFailed;
        }
    };
    for ([_]u32{ 2, 4 }) |n| {
        var failing: Failing = .{};
        try testing.expectError(error.SinkFailed, scan.scanAt(testing.allocator, io, tmp.dir, ".", .{
            .threads = n,
            .on_directory = .{ .context = &failing, .func = Failing.f },
        }));
        // Callbacks stop once the run has aborted.
        try testing.expectEqual(@as(usize, 3), failing.calls);
    }
}

test "allocation failure at any point of a parallel scan leaks nothing" {
    // `async_limit = .nothing` makes `Io.async` run every worker inline, so
    // the allocation sequence is deterministic while the whole parallel code
    // path (stack, nodes, discard mode) is still what runs.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = testIo(&threaded);

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const d = tmp.dir;
    try d.createDirPath(io, "a/b/c");
    try d.createDirPath(io, "a/x");
    try d.createDirPath(io, "z");
    try d.writeFile(io, .{ .sub_path = "a/b/f", .data = "f" });
    try d.hardLink("a/b/f", d, "z/g", io, .{});

    const opts: Options = .{ .threads = 3, .on_directory = .{ .func = ignoreDirectory } };

    var counting = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    const base = try scan.scanAt(counting.allocator(), io, d, ".", opts);
    const total_allocations = counting.allocations;
    try testing.expect(total_allocations > 0);
    try testing.expectEqual(@as(u64, 6), base.directories);

    var i: usize = 0;
    while (i < total_allocations) : (i += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        if (scan.scanAt(failing.allocator(), io, d, ".", opts)) |r| {
            try testing.expectEqual(base, r);
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}

fn ignoreDirectory(_: ?*anyopaque, _: []const u8, _: u32, _: Totals) scan.SinkError!void {}
