// SPDX-License-Identifier: MIT

//! `diskusage-demo` — a `du(1)`-shaped command-line tool built on the
//! `diskusage` module.
//!
//! **This is the `du` question, not the `df` one.** The sibling module
//! `diskfree` answers `df`: whole-filesystem space from `statfs(2)`, no
//! traversal at all. This one walks a tree and adds up what its files
//! actually occupy. The two share no symbol and neither imports the other.
//!
//! The demo exists to be diffed against real `du`, so its default output is
//! deliberately `du -B1`'s exact shape — `<bytes>\t<path>`, one line per
//! directory, subdirectories before their parents — and nothing else goes to
//! stdout. Everything the module knows that `du` cannot print goes to
//! `--explain`, which is the part worth reading:
//!
//!   * the **sparse gap**: apparent size minus real allocation, in one pass.
//!     `du` needs two runs (`du` and `du --apparent-size`) to show you this,
//!     and even then only as two numbers you subtract yourself.
//!   * the **hard-link saving**: how much was NOT counted because a second
//!     link to the same `(dev, ino)` had already been seen. `du` tells you
//!     nothing here; you would have to diff `du` against `du --count-links`.
//!   * which stat backend the host actually supports — `statx(2)` on
//!     anything modern, a raw per-architecture `fstatat` on a kernel too old
//!     for it.
//!
//! Failure handling is `du`'s, on purpose: an unreadable directory produces
//! one line on stderr, is still counted for its own size, does not stop the
//! walk, and makes the exit status 1 while the totals still print.
//!
//! Built against the PUBLISHED module (`@import("diskusage")`) only.

const std = @import("std");
const diskusage = @import("diskusage");

const Allocator = std.mem.Allocator;

const usage_text =
    \\diskusage-demo -- a du(1)-shaped tool for the `diskusage` module.
    \\
    \\usage:
    \\  diskusage-demo [options] [path ...]
    \\
    \\  -s              summarise: only the total for each argument
    \\  -d N            print directories at most N levels deep (du --max-depth=N)
    \\  -x              stay on one filesystem (du -x / --one-file-system)
    \\  -l              count every hard link, not once per (dev, ino)
    \\                  (du --count-links)
    \\  --apparent      report st_size instead of st_blocks*512
    \\                  (du --apparent-size)
    \\  --explain       after the table, print what du cannot: the sparse gap,
    \\                  the hard-link saving, the stat backend in use
    \\  -h, --help      this text
    \\
    \\Output is `<bytes>\t<path>`, one line per directory, deepest first --
    \\byte-for-byte the shape of `du -B1` (or `du --apparent-size -B1` with
    \\--apparent), so the two can be diffed directly.
    \\
    \\With no path argument, the current directory is scanned.
    \\
;

/// Build a tree whose byte total is known by construction, walk it, and check
/// the module agrees. The sizes are arithmetic a reader can redo, not a number
/// copied back out of a previous run.
fn selfDemo(io: std.Io, gpa: Allocator) !u8 {
    const base = ".zig-cache/diskusage-demo";
    const cwd = std.Io.Dir.cwd();
    cwd.deleteTree(io, base) catch {};
    defer cwd.deleteTree(io, base) catch {};
    try cwd.createDirPath(io, base ++ "/sub/deep");

    const files = [_]struct { path: []const u8, len: usize }{
        .{ .path = "a.bin", .len = 1000 },
        .{ .path = "sub/b.bin", .len = 2000 },
        .{ .path = "sub/deep/c.bin", .len = 3000 },
    };
    var apparent_total: u64 = 0;
    for (files) |f| {
        const blob = try gpa.alloc(u8, f.len);
        defer gpa.free(blob);
        @memset(blob, 'x');
        const full = try std.fmt.allocPrint(gpa, base ++ "/{s}", .{f.path});
        defer gpa.free(full);
        try cwd.writeFile(io, .{ .sub_path = full, .data = blob });
        apparent_total += f.len;
    }

    const report = try diskusage.scanPath(gpa, io, base, .{});

    if (report.total.apparent_bytes != apparent_total) {
        std.debug.print(
            "diskusage-demo: apparent total {d}, expected {d}\n",
            .{ report.total.apparent_bytes, apparent_total },
        );
        return error.ApparentTotalMismatch;
    }
    if (report.regular_files != files.len) {
        std.debug.print(
            "diskusage-demo: counted {d} regular files, expected {d}\n",
            .{ report.regular_files, files.len },
        );
        return error.FileCountMismatch;
    }
    // Real allocation is the filesystem's business -- block size and tail
    // packing -- so it is not pinned to a number. But 6000 bytes of written
    // data cannot occupy zero blocks, and on any real filesystem it occupies
    // at least as much as it apparently is only by coincidence, so the one
    // safe assertion is that something was allocated.
    if (report.total.allocated_bytes == 0) return error.AllocatedBytesZero;

    std.debug.print(
        "diskusage-demo: {d} files, {d} apparent bytes, {d} allocated -- totals check out\n" ++
            "run with a path to use it as du(1); --help for options\n",
        .{ report.regular_files, report.total.apparent_bytes, report.total.allocated_bytes },
    );
    return 0;
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A DebugAllocator that panics on leak makes the example a leak detector
    // for the module's ownership contract (CONVENTIONS.md §7.2).
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.next(); // argv[0]

    const opts = parseArgs(&args) catch {
        try printErr(io, "{s}", .{usage_text});
        return 2;
    };
    if (opts.help) {
        try printOut(io, "{s}", .{usage_text});
        return 0;
    }

    // No path given -> demonstrate and CHECK, rather than walking the current
    // directory. Defaulting to `.` is right for `du` and wrong for an example:
    // it printed six thousand lines whose content depended on the state of
    // this repository's build caches, and asserted nothing, so it agreed with
    // any answer the module gave. `zig build run-examples` runs every example
    // in the collection, and a gate cannot be built out of output like that.
    // Named paths still behave exactly like `du`.
    if (opts.n_paths == 0) return selfDemo(io, gpa);

    var out_buf: [16 * 1024]u8 = undefined;
    var out_w = std.Io.File.stdout().writer(io, &out_buf);
    const out = &out_w.interface;

    var any_error = false;
    var i: usize = 0;
    const paths = opts.paths[0..opts.n_paths];
    while (i < paths.len) : (i += 1) {
        if (try runOne(gpa, io, out, paths[i], opts)) any_error = true;
    }
    try out.flush();
    return if (any_error) 1 else 0;
}

/// Returns true if anything went wrong during the scan — `du` exits 1 in
/// that case and still prints its totals, which is what this mirrors.
fn runOne(gpa: Allocator, io: std.Io, out: *std.Io.Writer, path: []const u8, opts: Options) !bool {
    var printer: Printer = .{
        .out = out,
        .root = path,
        .opts = opts,
        .gpa = gpa,
    };
    defer printer.deinit();

    var reporter: Reporter = .{ .io = io };

    const report = diskusage.scanPath(gpa, io, path, .{
        .one_file_system = opts.one_file_system,
        .count_hard_links = opts.count_hard_links,
        .on_directory = .{ .context = &printer, .func = Printer.onDirectory },
        .on_error = .{ .context = &reporter, .func = Reporter.onError },
    }) catch |err| switch (err) {
        // The one error the module treats as fatal rather than skippable:
        // the scan root itself. Named explicitly, as CONVENTIONS.md §7.2
        // asks an example to do with at least one error.
        error.FileNotFound => {
            try printErr(io, "diskusage-demo: cannot access '{s}': no such file or directory\n", .{path});
            return true;
        },
        error.AccessDenied => {
            try printErr(io, "diskusage-demo: cannot access '{s}': permission denied\n", .{path});
            return true;
        },
        error.SinkFailed => {
            try printErr(io, "diskusage-demo: write failed while printing '{s}'\n", .{path});
            return true;
        },
        else => return err,
    };

    if (printer.write_error) |e| {
        try printErr(io, "diskusage-demo: write failed: {t}\n", .{e});
        return true;
    }

    // Flush the table before the explanation: stdout and stderr are
    // separately buffered, and a reader watching a terminal should see the
    // numbers before the commentary on them.
    if (opts.explain) {
        try out.flush();
        try explain(io, report, path);
    }
    return report.errors > 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// the du-shaped table
// ─────────────────────────────────────────────────────────────────────────────

/// Receives one call per directory, in `du`'s own order. Holds a scratch
/// buffer for joining the scan-root argument onto the module's root-relative
/// path, because the module deliberately hands over a borrowed relative path
/// rather than allocating a full one per directory.
const Printer = struct {
    out: *std.Io.Writer,
    root: []const u8,
    opts: Options,
    gpa: Allocator,
    joined: std.ArrayList(u8) = .empty,
    /// A sink cannot return a rich error (see `diskusage.SinkError`), so the
    /// real one is parked here for the caller to pick up — the pattern the
    /// module's doc comment describes.
    write_error: ?anyerror = null,

    fn deinit(self: *Printer) void {
        self.joined.deinit(self.gpa);
    }

    fn onDirectory(context: ?*anyopaque, rel: []const u8, depth: u32, totals: diskusage.Totals) diskusage.SinkError!void {
        const self: *Printer = @ptrCast(@alignCast(context.?));
        if (self.opts.summarise and depth != 0) return;
        if (self.opts.max_depth) |md| if (depth > md) return;

        self.joined.clearRetainingCapacity();
        self.joined.appendSlice(self.gpa, self.root) catch return error.SinkFailed;
        if (rel.len != 0) {
            self.joined.append(self.gpa, '/') catch return error.SinkFailed;
            self.joined.appendSlice(self.gpa, rel) catch return error.SinkFailed;
        }

        const bytes = if (self.opts.apparent) totals.apparent_bytes else totals.allocated_bytes;
        self.out.print("{d}\t{s}\n", .{ bytes, self.joined.items }) catch |e| {
            self.write_error = e;
            return error.SinkFailed;
        };
    }
};

/// One stderr line per failure, worded like `du`'s so the two are
/// comparable, and nothing on stdout so the table stays diffable.
const Reporter = struct {
    io: std.Io,

    fn onError(context: ?*anyopaque, path: []const u8, err: anyerror) void {
        const self: *Reporter = @ptrCast(@alignCast(context.?));
        const shown = if (path.len == 0) "." else path;
        printErr(self.io, "diskusage-demo: cannot read directory '{s}': {t}\n", .{ shown, err }) catch {};
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// --explain: the numbers du has no column for
// ─────────────────────────────────────────────────────────────────────────────

fn explain(io: std.Io, r: diskusage.Report, path: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    const e = &w.interface;

    try e.print(
        \\
        \\-- {s}
        \\   allocated (st_blocks*512, what plain du reports): {d} bytes
        \\   apparent  (st_size, what du --apparent-size reports): {d} bytes
        \\
    , .{ path, r.total.allocated_bytes, r.total.apparent_bytes });

    if (r.total.apparent_bytes > r.total.allocated_bytes) {
        try e.print(
            \\   sparse gap: {d} bytes of apparent size are not allocated. Both
            \\   numbers came from ONE traversal; du needs two runs to show it.
            \\
        , .{r.total.apparent_bytes - r.total.allocated_bytes});
    } else if (r.total.allocated_bytes > r.total.apparent_bytes) {
        try e.print(
            \\   allocation exceeds apparent size by {d} bytes -- ordinary: a
            \\   directory, or any file, occupies whole blocks.
            \\
        , .{r.total.allocated_bytes - r.total.apparent_bytes});
    }

    if (r.hard_links_skipped > 0) {
        try e.print(
            \\   hard links: {d} extra link(s) to an already-counted (dev, ino)
            \\   were not counted, saving {d} bytes. That is exactly the gap
            \\   between this run and `du --count-links` (`-l` here).
            \\
        , .{ r.hard_links_skipped, r.hard_link_bytes_skipped });
    }
    if (r.other_filesystems_skipped > 0) {
        try e.print("   {d} directory/ies on another filesystem were counted but not entered (-x).\n", .{r.other_filesystems_skipped});
    }
    try e.print(
        \\   {d} entries: {d} dir, {d} regular, {d} symlink, {d} other; {d} error(s).
        \\   stat backend: {t} (statx(2) where the kernel has it; a raw
        \\   per-architecture fstatat otherwise -- see the module's SPEC.md).
        \\
    , .{
        r.total.entries,
        r.directories,
        r.regular_files,
        r.symlinks,
        r.other,
        r.errors,
        diskusage.stat.detect(),
    });
    try e.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// arguments
// ─────────────────────────────────────────────────────────────────────────────

const Options = struct {
    help: bool = false,
    summarise: bool = false,
    max_depth: ?u32 = null,
    one_file_system: bool = false,
    count_hard_links: bool = false,
    apparent: bool = false,
    explain: bool = false,
    /// Raw argv slices — the process's own argv outlives `main`, so these
    /// need no allocation of their own.
    paths: [16][]const u8 = undefined,
    n_paths: usize = 0,
};

fn parseArgs(args: *std.process.Args.Iterator) !Options {
    var o: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            o.help = true;
        } else if (std.mem.eql(u8, arg, "-s")) {
            o.summarise = true;
        } else if (std.mem.eql(u8, arg, "-x")) {
            o.one_file_system = true;
        } else if (std.mem.eql(u8, arg, "-l")) {
            o.count_hard_links = true;
        } else if (std.mem.eql(u8, arg, "--apparent")) {
            o.apparent = true;
        } else if (std.mem.eql(u8, arg, "--explain")) {
            o.explain = true;
        } else if (std.mem.eql(u8, arg, "-d")) {
            const v = args.next() orelse return error.BadUsage;
            o.max_depth = std.fmt.parseInt(u32, v, 10) catch return error.BadUsage;
        } else if (arg.len > 0 and arg[0] == '-' and arg.len > 1) {
            return error.BadUsage;
        } else {
            if (o.n_paths >= o.paths.len) return error.BadUsage;
            o.paths[o.n_paths] = arg;
            o.n_paths += 1;
        }
    }
    return o;
}

fn printOut(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.print(fmt, args);
    try w.interface.flush();
}

fn printErr(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    try w.interface.print(fmt, args);
    try w.interface.flush();
}
