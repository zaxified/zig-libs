// SPDX-License-Identifier: MIT
//! The `du` traversal: walk a directory tree, `lstat` every entry, and
//! accumulate what it occupies — per subdirectory and in total.
//!
//! ## Where the traversal comes from
//!
//! `std.Io.Dir` in 0.16 offers `walk` and `walkSelectively`. This module
//! uses `walkSelectively` rather than hand-rolling a walker, and the choice
//! is not laziness — `walk` specifically would have been wrong:
//!
//!   * `walk` descends into every directory it finds, the moment it finds
//!     it. A one-filesystem boundary (`du -x`) is a decision made *between*
//!     seeing a directory and entering it, and only `walkSelectively`'s
//!     explicit `enter` provides that seam.
//!   * When `enter` fails — an unreadable directory, the single most
//!     ordinary failure a real `du` meets — nothing has been pushed, so the
//!     walk simply carries on in the parent. That is exactly `du`'s
//!     "complain and continue" behaviour, for free. With `walk`, the same
//!     failure surfaces from `next` and the caller cannot tell it apart
//!     from a failure to read the directory it was already inside.
//!   * `Walker.Entry` hands over the *open containing directory* plus a
//!     basename, which is what `stat.lstatAt` wants: one `fstatat` against
//!     an fd, instead of re-resolving every component of the path for every
//!     file, and no `PATH_MAX` ceiling on how deep a tree may be.
//!
//! What a hand-rolled walker would have added is a duplicate of std's stack
//! and name-buffer bookkeeping. What it would NOT have added is any of the
//! above.
//!
//! ⚠ One `walkSelectively` sharp edge this module has to work around:
//! `enter` refuses any entry whose `kind` is not `.directory`, and `kind`
//! comes from `getdents`' `d_type`, which several filesystems answer as
//! `.unknown`. A traversal that trusted it would silently never descend on
//! those. This module classifies from the `lstat` it performs anyway and
//! re-labels the entry before entering.

const std = @import("std");
const stat = @import("stat.zig");

const Allocator = std.mem.Allocator;

/// Everything one subtree occupies, in both of the units `du` can report.
///
/// **Both are always computed, in the same pass.** `du` makes this an
/// either/or flag (`--apparent-size`), but the two numbers come from two
/// fields of the same `lstat` — computing one and discarding the other buys
/// nothing, and forcing a caller to choose in advance means a caller that
/// wants both must walk the tree twice. Keeping both is also the only way
/// a caller can *see* the difference, which for a sparse file, a
/// tail-packed small file or a transparently compressed one is the whole
/// story.
pub const Totals = struct {
    /// Sum of `st_blocks * 512` — real allocation. This is what plain `du`
    /// reports.
    allocated_bytes: u64 = 0,
    /// Sum of `st_size` over everything that is **not a directory** — the
    /// apparent size, what `du --apparent-size` reports. For a sparse file
    /// this exceeds that file's `allocated_bytes` by the size of the hole.
    ///
    /// ⚠ **Directories contribute 0 here, and that is not an oversight.**
    /// A directory's own `st_size` is the size of the filesystem's index
    /// structure for it (4096 on ext4 for an empty one, a handful of bytes
    /// on tmpfs) — a property of the filesystem, not of "the data in this
    /// tree", which is what an apparent size is asking about. Both real
    /// implementations agree: measured here, `du --apparent-size -B1` and
    /// uutils' `du` each report `0` for an empty ext4 directory whose
    /// `st_size` is 4096, and both count symlinks, FIFOs and regular files
    /// by their `st_size` in the same run. Neither tool's documentation
    /// states this, so it is recorded as measured behaviour rather than
    /// cited. Including directories here — the obvious first
    /// implementation, and the one this module shipped for about an hour —
    /// makes every apparent-size total disagree with `du` by the sum of
    /// every directory's `st_size` in the tree.
    ///
    /// `allocated_bytes`, by contrast, DOES include directories: a
    /// directory really does occupy the blocks it occupies.
    apparent_bytes: u64 = 0,
    /// Number of entries whose sizes are included above.
    entries: u64 = 0,

    fn add(self: *Totals, other: Totals) void {
        self.allocated_bytes +|= other.allocated_bytes;
        self.apparent_bytes +|= other.apparent_bytes;
        self.entries +|= other.entries;
    }

    fn addEntry(self: *Totals, s: stat.FileStat) void {
        self.allocated_bytes +|= s.allocatedBytes();
        // See the `apparent_bytes` doc comment for why a directory's
        // st_size is excluded from this one sum and only this one.
        if (!s.isDir()) self.apparent_bytes +|= s.size;
        self.entries += 1;
    }
};

/// The result of one `scan`.
pub const Report = struct {
    /// The whole tree, root included.
    total: Totals = .{},
    /// The four kind counters below count exactly what was *counted*, so
    /// they always sum to `total.entries`. An entry dropped by hard-link
    /// de-duplication or by the one-filesystem boundary appears in neither,
    /// only in its own counter further down.
    directories: u64 = 0,
    regular_files: u64 = 0,
    symlinks: u64 = 0,
    /// Sockets, FIFOs, device nodes — counted, like `du` counts them, but
    /// tracked separately so a caller can see they were there.
    other: u64 = 0,
    /// Entries skipped because another link to the same `(dev, ino)` was
    /// already counted. Zero unless the tree actually contains hard links.
    hard_links_skipped: u64 = 0,
    /// Allocation that `hard_links_skipped` entries would have added had
    /// they been counted — i.e. exactly the difference between this scan
    /// and the same scan with `count_hard_links = true`.
    hard_link_bytes_skipped: u64 = 0,
    /// Entries — of any kind, not only directories — excluded because
    /// `one_file_system` was set and they live on a different device. They
    /// contribute nothing to any total; see `Options.one_file_system`.
    other_filesystems_skipped: u64 = 0,
    /// Entries that could not be stat'd or directories that could not be
    /// opened. Every one of them was also passed to `Options.on_error`.
    /// A nonzero value here is what a `du`-shaped tool turns into exit 1.
    errors: u64 = 0,
};

/// Called once per failure. Infallible on purpose: this is the reporting
/// channel for something that has already gone wrong, and a reporting
/// channel that can itself fail turns one failure into two.
///
/// `context` is carried through untouched — a bare function pointer with no
/// context forces a caller to keep its state in a file-scope global, which
/// is a defect this collection has paid for before.
pub const ErrorSink = struct {
    context: ?*anyopaque = null,
    func: *const fn (context: ?*anyopaque, path: []const u8, err: anyerror) void,

    fn report(self: ErrorSink, path: []const u8, err: anyerror) void {
        self.func(self.context, path, err);
    }
};

/// Called once per directory, after everything below it has been counted —
/// so subdirectories arrive before their parents and the scan root arrives
/// last. That is `du`'s own output order, and it is a consequence of the
/// traversal rather than a sort applied afterwards.
///
/// `path` is relative to the scan root, and is the empty string for the
/// root itself. It is borrowed: valid only for the duration of the call.
pub const DirSink = struct {
    context: ?*anyopaque = null,
    func: *const fn (context: ?*anyopaque, path: []const u8, depth: u32, totals: Totals) SinkError!void,

    fn report(self: DirSink, path: []const u8, depth: u32, totals: Totals) SinkError!void {
        return self.func(self.context, path, depth, totals);
    }
};

/// A `DirSink` may fail (it usually writes somewhere). It reports that as
/// one closed error rather than `anyerror`, and keeps the detail in its own
/// `context` where the caller can retrieve it — so `scan`'s error set stays
/// something a caller can exhaustively switch on.
pub const SinkError = error{SinkFailed};

pub const Options = struct {
    /// `du` counts a file with more than one link only once per traversal,
    /// keyed by `(st_dev, st_ino)`; `du --count-links` turns that off. The
    /// default here matches `du`'s default, because a caller comparing a
    /// number against `du`'s will otherwise disagree on any tree that has
    /// ever seen a backup tool, a package manager or `cp -l`.
    ///
    /// Directories are never de-duplicated even when this is `true` — they
    /// cannot be hard-linked, and `du` does not check them either.
    count_hard_links: bool = false,
    /// `du -x`: exclude anything that lives on a different device from the
    /// scan root — not counted at all, not just not descended into.
    ///
    /// ⚠ **The two reference implementations disagree here, and this
    /// follows GNU.** Measured on a fixture with a `tmpfs` mount and a
    /// bind-mounted file inside a `tmpfs` tree:
    ///
    ///   * a cross-device *directory*: GNU `du -x` and uutils `du -x` both
    ///     drop it entirely — no line, and its own 4096 bytes excluded from
    ///     the parent's total. An implementation that merely declines to
    ///     descend, and still counts the mount point itself, disagrees with
    ///     both by the size of every boundary directory.
    ///   * a cross-device *file* (a bind-mounted file, the only way to get
    ///     one): GNU `du -x` drops it too — total 4096 where the plain run
    ///     said 65536. uutils `du -x` keeps it, applying the boundary to
    ///     directories only. This module follows GNU: `-x` means one
    ///     filesystem, and a file on another device is on another
    ///     filesystem regardless of how it got there.
    ///
    /// The rule is applied where `fts` applies `FTS_XDEV` — while building
    /// the directory listing, before `du` itself ever sees the entry — so a
    /// filtered entry also never joins the hard-link set.
    one_file_system: bool = false,
    /// Which stat backend to use. `null` probes once per scan. Overriding
    /// it is for tests and for a caller that already knows.
    backend: ?stat.Backend = null,
    on_error: ?ErrorSink = null,
    on_directory: ?DirSink = null,
};

pub const ScanError = error{
    OutOfMemory,
    SinkFailed,
} || stat.StatError || std.Io.Dir.OpenError;

/// Scan `path`, resolved against `base`.
///
/// A `path` that is not a directory is not an error: it is stat'd and
/// reported on its own, which is what `du FILE` does.
///
/// Partial failure is the normal case, not an exception. An entry that
/// cannot be stat'd and a directory that cannot be opened are both counted
/// in `Report.errors`, passed to `Options.on_error`, and stepped over — the
/// scan still returns a total for everything it could read. Only a failure
/// on the scan root itself, and running out of memory, are fatal. That is
/// `du`'s behaviour (one stderr line per failure, exit 1, totals still
/// printed) and it is the behaviour the rest of this collection's
/// filesystem and `/proc` parsers already have.
pub fn scanAt(
    gpa: Allocator,
    io: std.Io,
    base: std.Io.Dir,
    path: []const u8,
    options: Options,
) ScanError!Report {
    const backend = options.backend orelse stat.detect();

    var report: Report = .{};

    // Same check `stat.lstatPath` makes, and for the same reason: an
    // embedded NUL is where `toPosixPath` either asserts (safety-checked
    // builds) or silently truncates the path (ReleaseFast) rather than
    // erroring — see `stat.StatError.InvalidPath`'s doc comment.
    if (std.mem.findScalar(u8, path, 0) != null) return error.InvalidPath;
    const path_z = std.posix.toPosixPath(path) catch return error.NameTooLong;
    const root_stat = try stat.lstatAt(backend, base.handle, &path_z);

    var links: std.AutoHashMapUnmanaged(stat.Id, void) = .empty;
    defer links.deinit(gpa);

    if (!root_stat.isDir()) {
        // `du FILE`. No traversal, no hard-link set: a single entry cannot
        // be a duplicate of anything.
        classify(&report, root_stat);
        report.total.addEntry(root_stat);
        if (options.on_directory) |sink| try sink.report("", 0, report.total);
        return report;
    }

    var dir = try base.openDir(io, path, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(io);

    var walker = try dir.walkSelectively(gpa);
    defer walker.deinit();

    var frames: std.ArrayList(Frame) = .empty;
    defer {
        for (frames.items) |f| gpa.free(f.path);
        frames.deinit(gpa);
    }

    {
        var root_totals: Totals = .{};
        root_totals.addEntry(root_stat);
        classify(&report, root_stat);
        try frames.append(gpa, .{ .path = try gpa.alloc(u8, 0), .totals = root_totals });
    }
    const root_device = root_stat.device();

    while (true) {
        const maybe_entry = walker.next(io) catch |err| {
            // `next` pops the directory it failed on, so the walk continues
            // in its parent — the depth bookkeeping below re-synchronises
            // by itself on the next entry. Out of memory is the one thing
            // that is not a per-entry problem.
            if (err == error.OutOfMemory) return error.OutOfMemory;
            report.errors += 1;
            if (options.on_error) |sink| sink.report(currentPath(frames.items), err);
            continue;
        };
        const entry = maybe_entry orelse break;
        const depth: u32 = @intCast(entry.depth());

        // Everything deeper than this entry's parent has finished.
        while (frames.items.len > depth) try closeFrame(gpa, &frames, options.on_directory);
        std.debug.assert(frames.items.len == depth);
        const parent = &frames.items[depth - 1];

        const st = stat.lstatAt(backend, entry.dir.handle, entry.basename) catch |err| {
            report.errors += 1;
            if (options.on_error) |sink| sink.report(entry.path, err);
            continue;
        };

        // The one-filesystem boundary, applied before anything else looks
        // at this entry: a filtered-out entry is not counted, not reported
        // to the directory sink, and never enters the hard-link set —
        // because in `fts` (which is what `du` walks with) `FTS_XDEV`
        // filters during the directory build, so `du` never sees it at all.
        // Applying it to EVERY kind, not just directories, is deliberate
        // and is the one place the two reference implementations disagree:
        // see `Options.one_file_system`.
        if (options.one_file_system and st.device() != root_device) {
            report.other_filesystems_skipped += 1;
            continue;
        }

        // Hard-link de-duplication, exactly where `du` does it: only for
        // non-directories with more than one link, so an ordinary tree pays
        // nothing for the hash map at all.
        if (!options.count_hard_links and !st.isDir() and st.nlink > 1) {
            const gop = try links.getOrPut(gpa, st.id());
            if (gop.found_existing) {
                report.hard_links_skipped += 1;
                report.hard_link_bytes_skipped +|= st.allocatedBytes();
                continue;
            }
        }

        classify(&report, st);

        if (!st.isDir()) {
            parent.totals.addEntry(st);
            continue;
        }

        // A directory. Its own size belongs to its own subtotal, which then
        // rolls into the parent when the frame closes.
        var sub: Totals = .{};
        sub.addEntry(st);

        // `enter` insists on `kind == .directory`, and `kind` comes from
        // `d_type`, which some filesystems report as `.unknown`. The stat
        // above already knows the truth, so say so.
        var dir_entry = entry;
        dir_entry.kind = .directory;
        walker.enter(io, dir_entry) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            // The ordinary case: an unreadable directory. It is counted —
            // it is a real entry with a real size — and not descended.
            report.errors += 1;
            if (options.on_error) |sink| sink.report(entry.path, err);
            if (options.on_directory) |sink| try sink.report(entry.path, depth, sub);
            parent.totals.add(sub);
            continue;
        };

        const owned = try gpa.dupe(u8, entry.path);
        errdefer gpa.free(owned);
        try frames.append(gpa, .{ .path = owned, .totals = sub });
    }

    while (frames.items.len > 1) try closeFrame(gpa, &frames, options.on_directory);

    const root_frame = frames.pop().?;
    defer gpa.free(root_frame.path);
    report.total = root_frame.totals;
    if (options.on_directory) |sink| try sink.report("", 0, root_frame.totals);

    return report;
}

/// Scan a path resolved against the current working directory (or an
/// absolute path).
pub fn scanPath(gpa: Allocator, io: std.Io, path: []const u8, options: Options) ScanError!Report {
    return scanAt(gpa, io, .cwd(), path, options);
}

/// One frame per directory currently open, indexed by depth: frame 0 is the
/// scan root. A frame owns a copy of its own path, because
/// `Walker.Entry.path` is invalidated by the next `next` call and a frame
/// outlives many of those.
const Frame = struct {
    path: []u8,
    totals: Totals,
};

/// Finish the deepest open directory: hand its subtotal to the sink, then
/// roll it into its parent. Never called on the root frame — the root is
/// closed by `scan` itself, after the loop, so that its subtotal is also
/// the `Report.total`.
fn closeFrame(gpa: Allocator, frames: *std.ArrayList(Frame), sink: ?DirSink) SinkError!void {
    const f = frames.pop().?;
    defer gpa.free(f.path);
    const depth: u32 = @intCast(frames.items.len);
    if (sink) |s| try s.report(f.path, depth, f.totals);
    frames.items[frames.items.len - 1].totals.add(f.totals);
}

/// Best-effort path for a failure the walker reported without one: the
/// deepest directory still open, which is where `next` was reading. The
/// empty string means the scan root.
fn currentPath(frames: []const Frame) []const u8 {
    if (frames.len == 0) return "";
    return frames[frames.len - 1].path;
}

fn classify(report: *Report, s: stat.FileStat) void {
    if (s.isDir()) {
        report.directories += 1;
    } else if (s.isSymLink()) {
        report.symlinks += 1;
    } else if (s.isRegular()) {
        report.regular_files += 1;
    } else {
        report.other += 1;
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");
const linux = std.os.linux;

/// The fixture every traversal test below is built on, mirroring the tree
/// used to diff this module against real `du`:
///
///   plain/data.bin      5000 bytes of real content
///   sparse/hole.img     1 MiB apparent, one block allocated
///   links/a/orig.bin    20000 bytes, hard-linked as links/b/same.bin
///   syms/valid.lnk      symlink to ../plain/data.bin (never followed)
///   syms/loop.lnk       symlink to `..` — a directory, and a cycle if followed
///   empty/              an empty directory
///   odd/pipe            a FIFO (a kind that is neither file, dir nor symlink)
///
/// The unreadable directory is created only by the test that needs it, so
/// that every other test's `cleanup` can delete the tree.
const Fixture = struct {
    tmp: testing.TmpDir,
    io: std.Io,

    const hole_size = 1 << 20;
    const plain_size = 5000;
    const link_size = 20000;

    fn init(io: std.Io) !Fixture {
        var f: Fixture = .{ .tmp = testing.tmpDir(.{ .iterate = true }), .io = io };
        errdefer f.tmp.cleanup();
        const d = f.tmp.dir;

        try d.createDirPath(io, "plain");
        try d.writeFile(io, .{ .sub_path = "plain/data.bin", .data = &[_]u8{0xab} ** plain_size });

        try d.createDirPath(io, "sparse");
        {
            var file = try d.createFile(io, "sparse/hole.img", .{});
            defer file.close(io);
            // A pure hole: `setLength` past the end allocates no data
            // blocks on any filesystem this runs on, so st_size is a
            // megabyte and st_blocks stays near zero.
            try file.setLength(io, hole_size);
        }

        try d.createDirPath(io, "links/a");
        try d.createDirPath(io, "links/b");
        try d.writeFile(io, .{ .sub_path = "links/a/orig.bin", .data = &[_]u8{0xcd} ** link_size });
        try d.hardLink("links/a/orig.bin", d, "links/b/same.bin", io, .{});

        try d.createDirPath(io, "syms");
        try d.symLink(io, "../plain/data.bin", "syms/valid.lnk", .{});
        try d.symLink(io, "..", "syms/loop.lnk", .{});

        try d.createDirPath(io, "empty");

        try d.createDirPath(io, "odd");
        const rc = linux.mknodat(d.handle, "odd/pipe", linux.S.IFIFO | 0o644, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;

        return f;
    }

    fn deinit(f: *Fixture) void {
        f.tmp.cleanup();
    }
};

fn scanFixture(gpa: Allocator, f: *Fixture, options: Options) !Report {
    return scanAt(gpa, f.io, f.tmp.dir, ".", options);
}

test "hard links: a second link to the same (dev, ino) is counted once" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    const deduped = try scanFixture(testing.allocator, &f, .{});
    const counted = try scanFixture(testing.allocator, &f, .{ .count_hard_links = true });

    // The tree has exactly one extra link.
    try testing.expectEqual(@as(u64, 1), deduped.hard_links_skipped);
    try testing.expectEqual(@as(u64, 0), counted.hard_links_skipped);

    // The two runs differ by exactly the skipped file's allocation — the
    // relationship, not a hardcoded number, so the assertion holds on any
    // filesystem's block size.
    try testing.expect(deduped.hard_link_bytes_skipped > 0);
    try testing.expectEqual(
        counted.total.allocated_bytes,
        deduped.total.allocated_bytes + deduped.hard_link_bytes_skipped,
    );
    // ...and the apparent totals differ by exactly the file's st_size.
    try testing.expectEqual(
        counted.total.apparent_bytes,
        deduped.total.apparent_bytes + Fixture.link_size,
    );
    // The de-duplicated entry is not counted at all: one fewer entry.
    try testing.expectEqual(counted.total.entries, deduped.total.entries + 1);
}

test "hard links: de-duplication keys on (dev, ino), not on inode alone" {
    // A directory is never de-duplicated even though many share a link
    // count above one (every directory with subdirectories does). If the
    // rule keyed on `nlink > 1` alone and forgot the "not a directory"
    // half, `links/` — nlink 4 — would be dropped from its parent's total.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    const r = try scanFixture(testing.allocator, &f, .{});
    // 9 directories: root, plain, sparse, links, links/a, links/b, syms,
    // empty, odd.
    try testing.expectEqual(@as(u64, 9), r.directories);
    try testing.expectEqual(@as(u64, 1), r.hard_links_skipped);
}

test "sparse file: apparent size exceeds allocation by the size of the hole" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    var sink: CollectSink = .{ .gpa = testing.allocator };
    defer sink.deinit();

    _ = try scanFixture(testing.allocator, &f, .{
        .on_directory = .{ .context = &sink, .func = CollectSink.onDirectory },
    });

    const sparse = sink.find("sparse") orelse return error.TestUnexpectedResult;
    // The whole megabyte is apparent...
    try testing.expectEqual(@as(u64, Fixture.hole_size), sparse.apparent_bytes);
    // ...and almost none of it is allocated. A traversal that summed
    // st_size and called it disk usage would report a megabyte here.
    try testing.expect(sparse.allocated_bytes < Fixture.hole_size / 16);
}

test "directories: counted in allocation, excluded from apparent size" {
    // The rule both real `du` implementations follow and neither documents.
    // `empty/` contains nothing, so every byte either total attributes to
    // it is the directory's own.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    var sink: CollectSink = .{ .gpa = testing.allocator };
    defer sink.deinit();

    _ = try scanFixture(testing.allocator, &f, .{
        .on_directory = .{ .context = &sink, .func = CollectSink.onDirectory },
    });

    const empty = sink.find("empty") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, 1), empty.entries);
    // Apparent size of a directory is always zero, whatever st_size says —
    // and st_size is nonzero for a directory on every filesystem (4096 on
    // ext4, tens of bytes on tmpfs).
    try testing.expectEqual(@as(u64, 0), empty.apparent_bytes);
}

test "symlinks: never followed, counted by their own size" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    var sink: CollectSink = .{ .gpa = testing.allocator };
    defer sink.deinit();

    const r = try scanFixture(testing.allocator, &f, .{
        .on_directory = .{ .context = &sink, .func = CollectSink.onDirectory },
    });

    try testing.expectEqual(@as(u64, 2), r.symlinks);

    const syms = sink.find("syms") orelse return error.TestUnexpectedResult;
    // Three entries: the directory itself plus two links. If `syms/loop.lnk`
    // (which points at `..`) had been followed, the walk would have
    // re-entered the fixture root and this count would be far higher — or
    // the scan would not terminate at all.
    try testing.expectEqual(@as(u64, 3), syms.entries);
    // The apparent size of the two links is the length of their target
    // strings ("../plain/data.bin" = 17, ".." = 2), not the size of what
    // they point at (5000 bytes and a whole directory tree).
    try testing.expectEqual(@as(u64, 17 + 2), syms.apparent_bytes);
}

test "FIFOs and other kinds are counted, and classified apart" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    const r = try scanFixture(testing.allocator, &f, .{});
    try testing.expectEqual(@as(u64, 1), r.other);
    // plain/data.bin, sparse/hole.img and ONE of the two hard-linked
    // copies: the kind counters count what was counted, so they always add
    // up to `total.entries`, which the de-duplicated link is also absent
    // from. Counting it here and not there would make the two disagree.
    try testing.expectEqual(@as(u64, 3), r.regular_files);
    try testing.expectEqual(
        r.total.entries,
        r.directories + r.regular_files + r.symlinks + r.other,
    );
}

test "unreadable directory: reported, counted, and stepped over" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    const d = f.tmp.dir;
    try d.createDirPath(io, "locked");
    try d.writeFile(io, .{ .sub_path = "locked/secret.bin", .data = &[_]u8{1} ** 9000 });
    if (linux.errno(linux.fchmodat(d.handle, "locked", 0o000)) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.fchmodat(d.handle, "locked", 0o755); // so cleanup can delete it

    // Running as root defeats the whole premise.
    if (d.openDir(io, "locked", .{ .iterate = true })) |*probe| {
        @constCast(probe).close(io);
        return error.SkipZigTest;
    } else |_| {}

    var errs: ErrorCollector = .{};
    var sink: CollectSink = .{ .gpa = testing.allocator };
    defer sink.deinit();

    const r = try scanFixture(testing.allocator, &f, .{
        .on_error = .{ .context = &errs, .func = ErrorCollector.onError },
        .on_directory = .{ .context = &sink, .func = CollectSink.onDirectory },
    });

    // The scan did NOT abort: it still returned totals for everything else.
    try testing.expect(r.total.allocated_bytes > 0);
    try testing.expectEqual(@as(u64, 1), r.errors);
    try testing.expectEqual(@as(usize, 1), errs.count);
    try testing.expectEqual(anyerror.AccessDenied, errs.last_err.?);
    try testing.expectEqualStrings("locked", errs.last_path[0..errs.last_path_len]);

    // The directory itself is still counted — it is a real entry with a
    // real size — even though nothing inside it could be reached. The 9000
    // bytes inside are not.
    const locked = sink.find("locked") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, 1), locked.entries);
    try testing.expect(locked.allocated_bytes < 9000);
}

test "directory subtotals arrive post-order: children first, root last" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    var sink: CollectSink = .{ .gpa = testing.allocator };
    defer sink.deinit();

    const r = try scanFixture(testing.allocator, &f, .{
        .on_directory = .{ .context = &sink, .func = CollectSink.onDirectory },
    });

    try testing.expectEqual(@as(usize, 9), sink.entries.items.len);
    // The root is last, is at depth 0, and its subtotal IS the report total.
    const last = sink.entries.items[sink.entries.items.len - 1];
    try testing.expectEqualStrings("", last.path);
    try testing.expectEqual(@as(u32, 0), last.depth);
    try testing.expectEqual(r.total.allocated_bytes, last.totals.allocated_bytes);
    try testing.expectEqual(r.total.apparent_bytes, last.totals.apparent_bytes);
    try testing.expectEqual(r.total.entries, last.totals.entries);

    // Every child appears before its parent.
    for (sink.entries.items, 0..) |e, i| {
        if (e.path.len == 0) continue;
        const parent_rel = std.fs.path.dirname(e.path) orelse "";
        const parent_index = sink.indexOf(parent_rel) orelse return error.TestUnexpectedResult;
        try testing.expect(parent_index > i);
    }

    // A parent's subtotal includes its children's: links = links/a + links/b
    // plus links' own size.
    const links = sink.find("links").?;
    const a = sink.find("links/a").?;
    const b = sink.find("links/b").?;
    try testing.expect(links.allocated_bytes >= a.allocated_bytes + b.allocated_bytes);
    try testing.expectEqual(links.entries, a.entries + b.entries + 1);
}

test "scanning a plain file is not an error" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    var sink: CollectSink = .{ .gpa = testing.allocator };
    defer sink.deinit();

    const r = try scanAt(testing.allocator, io, f.tmp.dir, "plain/data.bin", .{
        .on_directory = .{ .context = &sink, .func = CollectSink.onDirectory },
    });
    try testing.expectEqual(@as(u64, 1), r.total.entries);
    try testing.expectEqual(@as(u64, 1), r.regular_files);
    try testing.expectEqual(@as(u64, 0), r.directories);
    try testing.expectEqual(@as(u64, Fixture.plain_size), r.total.apparent_bytes);
    // Even the degenerate case reports through the same sink, so a caller
    // does not need a second code path for it.
    try testing.expectEqual(@as(usize, 1), sink.entries.items.len);
}

test "a missing scan root is fatal, unlike a missing entry inside the tree" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    try testing.expectError(error.FileNotFound, scanAt(testing.allocator, io, f.tmp.dir, "no-such-thing", .{}));
}

test "a failing DirSink stops the scan with SinkFailed" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    var failer: FailingSink = .{};
    try testing.expectError(error.SinkFailed, scanFixture(testing.allocator, &f, .{
        .on_directory = .{ .context = &failer, .func = FailingSink.onDirectory },
    }));
    try testing.expect(failer.calls >= 1);
}

test "one_file_system: nothing is skipped when the tree is on one device" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    const plain = try scanFixture(testing.allocator, &f, .{});
    const bounded = try scanFixture(testing.allocator, &f, .{ .one_file_system = true });
    try testing.expectEqual(@as(u64, 0), bounded.other_filesystems_skipped);
    try testing.expectEqual(plain.total.allocated_bytes, bounded.total.allocated_bytes);
    try testing.expectEqual(plain.total.entries, bounded.total.entries);
}

test "one_file_system: a real mount boundary is excluded, contents and all" {
    // `/sys/fs` is a plain sysfs directory whose children include several
    // mount points (cgroup2, bpf, pstore, ...) on their own devices. No
    // privileges are needed to walk it.
    //
    // ⚠ The skip condition below is deliberately established WITHOUT calling
    // `scanAt` — it counts the boundary children with `stat.lstatAt`
    // directly. An earlier version asked the scan itself
    // ("`other_filesystems_skipped == 0` ⇒ skip"), which meant that
    // disabling the boundary check made this test *skip* instead of fail:
    // it went green under exactly the mutation it exists to catch. A
    // precondition may never be read off the mechanism under test.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const probe_root = "/sys/fs";
    const backend = stat.detect();
    const root_st = stat.lstatPath(backend, probe_root) catch return error.SkipZigTest;

    var dir = std.Io.Dir.cwd().openDir(io, probe_root, .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(io);

    var boundary_children: u64 = 0;
    var it = dir.iterate();
    while (it.next(io) catch return error.SkipZigTest) |entry| {
        const name_z = std.posix.toPosixPath(entry.name) catch continue;
        const st = stat.lstatAt(backend, dir.handle, &name_z) catch continue;
        if (st.device() != root_st.device()) boundary_children += 1;
    }
    if (boundary_children == 0) return error.SkipZigTest; // this host has no boundary there

    const plain = scanPath(testing.allocator, io, probe_root, .{}) catch return error.SkipZigTest;
    const bounded = try scanPath(testing.allocator, io, probe_root, .{ .one_file_system = true });

    // At least the children counted above; possibly more, since a mount can
    // itself contain a further mount that the unbounded scan descends into.
    try testing.expect(bounded.other_filesystems_skipped >= boundary_children);
    try testing.expect(bounded.total.entries < plain.total.entries);
    try testing.expect(bounded.directories < plain.directories);
}

test "allocation failure at any point leaks nothing and is reported" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fixture.init(io);
    defer f.deinit();

    // How many allocations a full run makes, then fail at each index in
    // turn. `std.testing.allocator` backs the failing allocator, so any
    // block not freed on the error path is reported at teardown.
    var counting = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    _ = try scanFixture(counting.allocator(), &f, .{});
    const total_allocations = counting.allocations;
    try testing.expect(total_allocations > 0);

    var i: usize = 0;
    while (i < total_allocations) : (i += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        const result = scanFixture(failing.allocator(), &f, .{});
        // Either it survived (the failed allocation was not on a path this
        // run took) or it reported out of memory. Never anything else.
        if (result) |_| {} else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}

// ── test helpers ────────────────────────────────────────────────────────────

/// Records every directory subtotal, in the order the sink delivered it.
const CollectSink = struct {
    gpa: Allocator,
    entries: std.ArrayList(Entry) = .empty,

    const Entry = struct { path: []u8, depth: u32, totals: Totals };

    fn deinit(self: *CollectSink) void {
        for (self.entries.items) |e| self.gpa.free(e.path);
        self.entries.deinit(self.gpa);
    }

    fn onDirectory(context: ?*anyopaque, path: []const u8, depth: u32, totals: Totals) SinkError!void {
        const self: *CollectSink = @ptrCast(@alignCast(context.?));
        const owned = self.gpa.dupe(u8, path) catch return error.SinkFailed;
        self.entries.append(self.gpa, .{ .path = owned, .depth = depth, .totals = totals }) catch {
            self.gpa.free(owned);
            return error.SinkFailed;
        };
    }

    fn find(self: *const CollectSink, path: []const u8) ?Totals {
        for (self.entries.items) |e| if (std.mem.eql(u8, e.path, path)) return e.totals;
        return null;
    }

    fn indexOf(self: *const CollectSink, path: []const u8) ?usize {
        for (self.entries.items, 0..) |e, i| if (std.mem.eql(u8, e.path, path)) return i;
        return null;
    }
};

/// Records the last failure without allocating, so it is safe to use on a
/// path that is already out of memory.
const ErrorCollector = struct {
    count: usize = 0,
    last_err: ?anyerror = null,
    last_path: [256]u8 = undefined,
    last_path_len: usize = 0,

    fn onError(context: ?*anyopaque, path: []const u8, err: anyerror) void {
        const self: *ErrorCollector = @ptrCast(@alignCast(context.?));
        self.count += 1;
        self.last_err = err;
        const n = @min(path.len, self.last_path.len);
        @memcpy(self.last_path[0..n], path[0..n]);
        self.last_path_len = n;
    }
};

const FailingSink = struct {
    calls: usize = 0,

    fn onDirectory(context: ?*anyopaque, path: []const u8, depth: u32, totals: Totals) SinkError!void {
        _ = path;
        _ = depth;
        _ = totals;
        const self: *FailingSink = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        return error.SinkFailed;
    }
};
