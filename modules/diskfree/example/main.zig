// SPDX-License-Identifier: MIT

//! `diskfree-demo` — a `df(1)`-shaped command-line tool built on the
//! `diskfree` module: filesystem space for every mounted filesystem (or a
//! given set of paths), plus the two mount-table views the module parses.
//!
//! ⚠⚠ **This is the `df` question, not the `du` one — say it plainly, because
//! the module's own name invites the opposite guess.** `du` walks a
//! directory tree, `lstat`s every file, and *accumulates* real disk
//! allocation (`st_blocks`) per subtree. `diskfree` does none of that: it
//! is a `statfs(2)`/`statfs64(2)` syscall wrapper (whole-filesystem space)
//! plus `/proc/self/mounts`/`mountinfo` parsers. This demo therefore walks
//! no directories, stats no files, and accumulates no sizes — it can only
//! ever answer "how full is this filesystem", never "how much space do
//! these files use". That second question belongs to the sibling
//! `diskusage` module, which exists for it: the portable `std.Io.File.Stat`
//! this collection otherwise uses carries neither `st_blocks` (the real
//! block allocation `du` counts, as opposed to the logical file size) nor
//! `st_dev` (needed to stop at a filesystem boundary, `du -x`), so it wraps
//! `statx`/`fstatat` directly — the same kind of raw-syscall wrapper
//! `statfs.zig` is here.
//!
//! **The `f_bfree`/`f_bavail` split is the module's one deliberate
//! departure from a naive port**, and this demo makes it visible rather than
//! collapsing it: the space table's "Used" column is computed from
//! `f_bfree` (`Usage.blocks_free`) exactly the way real `df` computes it —
//! `blocks_total - blocks_free`, NOT `blocks_total - blocks_available` —
//! while "Available" and "Use%" come from `f_bavail`
//! (`Usage.blocks_available`). A port that only kept one of the two fields
//! could not reproduce both columns at once. The footer after the table
//! spells out the gap (`blocks_free - blocks_available`) as the root-
//! reserved margin `df` itself never labels.
//!
//! **`mounts` vs `mountinfo`.** The main table's "Filesystem"/"Mounted on"
//! columns come from `mounts.readMounts` — the same four-column shape
//! `/etc/mtab` and `mount(8)`'s traditional output use. `--mountinfo` prints
//! the richer source instead and adds a "Propagation" column
//! (`shared:N`/`master:N`/`propagate_from:N`/`unbindable`) that `mounts.zig`
//! cannot express at all — its four columns have no field for it. That is
//! the concrete answer to "what does the richer parser give you".
//!
//! Built against the PUBLISHED module (`@import("diskfree")`) only.

const std = @import("std");
const diskfree = @import("diskfree");

const Allocator = std.mem.Allocator;

const not_du_banner =
    \\diskfree-demo answers the `df` question (how full is this filesystem?),
    \\NOT the `du` one (how much space do these files use?). The `diskfree`
    \\module walks no directories and stats no files -- it wraps statfs(2) and
    \\parses /proc/self/mounts. A real `du` would need a raw stat/lstat syscall
    \\wrapper first (st_blocks + st_dev, neither in std.Io.File.Stat) plus a
    \\directory walker; neither exists in this module today.
    \\
;

const usage_text =
    \\diskfree-demo -- a df(1)-shaped tool for the `diskfree` module.
    \\NOT a `du` tool -- see the banner above (run with no flags) or the header
    \\comment in example/main.zig for why, and what building `du` would need.
    \\
    \\usage:
    \\  diskfree-demo [-a] [path ...]     filesystem space report (df-shaped)
    \\  diskfree-demo --mounts             /proc/self/mounts table (mtab-shaped)
    \\  diskfree-demo --mountinfo          /proc/self/mountinfo table (adds
    \\                                      propagation info `mounts` can't show)
    \\  diskfree-demo --margin [path ...]  f_bfree vs f_bavail, explained
    \\
    \\  -a            include pseudo/dummy filesystems (0 total blocks) --
    \\                same idea as df's own -a
    \\  -h, --help    this text
    \\
    \\With no `path` arguments, the space/margin reports cover every entry in
    \\/proc/self/mounts. With one or more paths, each is queried directly via
    \\statfs(2) -- like `df /some/path` -- and shown as given (this demo does
    \\not canonicalize the path or resolve symlinks: std.Io.Dir has no
    \\`realpath` in Zig 0.16, so "Mounted on" for an explicit path is a
    \\best-effort longest-prefix match against the mount table, not a
    \\guaranteed-exact one).
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak
    // detector for the module's ownership contract (CONVENTIONS.md §7.2).
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
        return 1;
    };

    return switch (opts.mode) {
        .help => blk: {
            try printOut(io, "{s}", .{usage_text});
            break :blk 0;
        },
        .space => runSpace(gpa, io, opts),
        .mounts => runMounts(gpa, io),
        .mountinfo => runMountinfo(gpa, io),
        .margin => runMargin(gpa, io, opts),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// arguments
// ─────────────────────────────────────────────────────────────────────────────

const Mode = enum { help, space, mounts, mountinfo, margin };

const Options = struct {
    mode: Mode = .space,
    all: bool = false,
    /// Raw argv slices -- the process's own argv outlives `main`, so these
    /// need no allocation/ownership of their own (same assumption
    /// `procnet-demo` makes for its flag parsing).
    paths: [16][]const u8 = undefined,
    n_paths: usize = 0,
};

fn parseArgs(args: *std.process.Args.Iterator) !Options {
    var o: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            o.mode = .help;
        } else if (std.mem.eql(u8, arg, "--mounts")) {
            o.mode = .mounts;
        } else if (std.mem.eql(u8, arg, "--mountinfo")) {
            o.mode = .mountinfo;
        } else if (std.mem.eql(u8, arg, "--margin")) {
            o.mode = .margin;
        } else if (std.mem.eql(u8, arg, "-a")) {
            o.all = true;
        } else if (arg.len > 0 and arg[0] == '-') {
            return error.BadUsage;
        } else {
            if (o.n_paths >= o.paths.len) return error.BadUsage;
            o.paths[o.n_paths] = arg;
            o.n_paths += 1;
        }
    }
    return o;
}

// ─────────────────────────────────────────────────────────────────────────────
// space report -- the `df` table itself
// ─────────────────────────────────────────────────────────────────────────────

fn runSpace(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    try printBanner(io);

    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;

    try out.print("{s:<16} {s:>10} {s:>10} {s:>10} {s:>5} {s}\n", .{
        "Filesystem", "1K-blocks", "Used", "Available", "Use%", "Mounted on",
    });

    var max_margin_1k: u64 = 0;
    var max_margin_row: [256]u8 = undefined;
    var max_margin_row_len: usize = 0;
    var shown: usize = 0;
    var skipped_dummy: usize = 0;
    var unreadable: usize = 0;

    if (opts.n_paths > 0) {
        // Explicit paths: query each directly, like `df /some/path ...`.
        const mnts = try diskfree.mounts.readMounts(gpa, io);
        defer if (mnts) |m| diskfree.mounts.freeAll(gpa, m);

        for (opts.paths[0..opts.n_paths]) |p| {
            const u = diskfree.statfs.query(p) catch |err| {
                try out.print("{s:<16} {s:>10} {s:>10} {s:>10} {s:>5} {s} ({t})\n", .{ p, "-", "-", "-", "-", p, err });
                unreadable += 1;
                continue;
            };
            const mp = if (mnts) |m| bestMatch(p, m) else null;
            const device = if (mp) |e| e.device else "-";
            const label = if (mp) |e| e.mount_point else p;
            try printSpaceRow(out, device, label, u);
            shown += 1;
            trackMargin(u, device, label, &max_margin_1k, &max_margin_row, &max_margin_row_len);
        }
    } else {
        const mnts = try diskfree.mounts.readMounts(gpa, io) orelse @constCast(&.{});
        defer diskfree.mounts.freeAll(gpa, mnts);

        for (mnts) |m| {
            const u = diskfree.statfs.query(m.mount_point) catch {
                unreadable += 1;
                continue;
            };
            // Dummy-filesystem filter: real df's own definition is a fixed
            // list of pseudo fs types (proc, sysfs, cgroup, ...); this demo
            // uses the simpler proxy `blocks_total == 0` (every such
            // filesystem this host has reports zero blocks from statfs(2)
            // anyway) rather than duplicating that list.
            if (u.blocks_total == 0 and !opts.all) {
                skipped_dummy += 1;
                continue;
            }
            try printSpaceRow(out, m.device, m.mount_point, u);
            shown += 1;
            trackMargin(u, m.device, m.mount_point, &max_margin_1k, &max_margin_row, &max_margin_row_len);
        }
    }

    try out.print(
        \\
        \\-- {d} filesystem(s) shown
    , .{shown});
    if (skipped_dummy > 0) try out.print(", {d} pseudo/dummy filesystem(s) hidden (pass -a to show)", .{skipped_dummy});
    if (unreadable > 0) try out.print(", {d} unreadable", .{unreadable});
    try out.writeAll(".\n");

    if (max_margin_1k > 0) {
        try out.print(
            \\-- root-reserved margin: f_bfree includes space df's "Available" column
            \\   deliberately excludes (f_bavail). Largest gap seen: {d} 1K-blocks on
            \\   {s}. Read Usage.blocks_available (or availableBytes()), not
            \\   Usage.blocks_free, if you want df's number.
            \\
        , .{ max_margin_1k, max_margin_row[0..max_margin_row_len] });
    } else {
        try out.writeAll("-- every filesystem shown has f_bfree == f_bavail (no root-reserved margin observed).\n");
    }

    try out.flush();
    return 0;
}

fn printSpaceRow(out: *std.Io.Writer, device: []const u8, mount_point: []const u8, u: diskfree.Usage) !void {
    const total_1k = u.totalBytes() / 1024;
    // Matches real df/gnudf/uutils-df exactly (verified against both --
    // see CHANGELOG): "Used" is total minus RAW free (f_bfree), not minus
    // available (f_bavail). Using f_bavail here would silently disagree
    // with every real `df` by exactly the root-reserved margin.
    const free_1k = u.freeBytes() / 1024;
    const avail_1k = u.availableBytes() / 1024;
    const used_1k = if (total_1k >= free_1k) total_1k - free_1k else 0;

    var pct_buf: [5]u8 = undefined;
    const pct_str = formatUsePercent(&pct_buf, used_1k, avail_1k);

    try out.print("{s:<16} {d:>10} {d:>10} {d:>10} {s:>5} {s}\n", .{
        device,
        total_1k,
        used_1k,
        avail_1k,
        pct_str,
        mount_point,
    });
}

/// GNU df's own use-percentage formula (verified numerically against a live
/// `df`/`gnudf` run on this host's ext4 root, byte-for-byte): ceiling of
/// `used * 100 / (used + available)`. The denominator is `used + available`
/// (equivalently `blocks_total` minus the root-reserved margin), not
/// `blocks_total` itself -- reproduced exactly here, verbatim, because it is
/// what this demo's own table is diffed against. `SPEC.md`'s own
/// "use-percentage rounding" note documents that OTHER implementations
/// (busybox: round-to-nearest) legitimately disagree with this by up to one
/// point; that disagreement is not a bug in either side.
fn formatUsePercent(buf: *[5]u8, used_1k: u64, avail_1k: u64) []const u8 {
    const denom = used_1k + avail_1k;
    if (denom == 0) return "    -";
    const pct = (used_1k * 100 + denom - 1) / denom; // ceiling division
    return std.fmt.bufPrint(buf, "{d:>3}%", .{pct}) catch "?";
}

fn trackMargin(u: diskfree.Usage, device: []const u8, mount_point: []const u8, max_margin_1k: *u64, row_buf: []u8, row_len: *usize) void {
    const free_1k = u.freeBytes() / 1024;
    const avail_1k = u.availableBytes() / 1024;
    if (free_1k <= avail_1k) return;
    const margin = free_1k - avail_1k;
    if (margin <= max_margin_1k.*) return;
    max_margin_1k.* = margin;
    const s = std.fmt.bufPrint(row_buf, "{s} ({s})", .{ mount_point, device }) catch {
        row_len.* = 0;
        return;
    };
    row_len.* = s.len;
}

/// Longest-`mount_point`-prefix match for an explicit path argument -- see
/// the usage text's caveat: no `realpath` in 0.16, so this is best-effort on
/// an already-reasonable (typically absolute) path, not a guaranteed-exact
/// resolution the way `df PATH` does via `st_dev`.
fn bestMatch(path: []const u8, entries: []diskfree.mounts.MountEntry) ?diskfree.mounts.MountEntry {
    var best: ?diskfree.mounts.MountEntry = null;
    var best_len: usize = 0;
    for (entries) |e| {
        if (e.mount_point.len > best_len and std.mem.startsWith(u8, path, e.mount_point)) {
            best = e;
            best_len = e.mount_point.len;
        }
    }
    return best;
}

// ─────────────────────────────────────────────────────────────────────────────
// --margin -- f_bfree vs f_bavail, spelled out explicitly
// ─────────────────────────────────────────────────────────────────────────────

fn runMargin(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    try printBanner(io);

    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;

    try out.writeAll(
        \\Every row below queries the SAME statfs(2) call twice-over: f_bfree
        \\(raw free, "Free") and f_bavail (unprivileged-usable free, "Avail")
        \\are two different kernel counters, not two names for one number.
        \\"Margin" = Free - Avail = the filesystem's superuser-reserved space
        \\(ext-family: `tune2fs -m`; 0 on most non-ext filesystems).
        \\
        \\
    );
    try out.print("{s:<16} {s:>12} {s:>12} {s:>10} {s}\n", .{ "Mounted on", "Free(1K)", "Avail(1K)", "Margin(1K)", "fstype magic" });

    if (opts.n_paths > 0) {
        for (opts.paths[0..opts.n_paths]) |p| {
            const u = diskfree.statfs.query(p) catch |err| {
                try out.print("{s:<16} (unreadable: {t})\n", .{ p, err });
                continue;
            };
            try printMarginRow(out, p, u);
        }
    } else {
        const mnts = try diskfree.mounts.readMounts(gpa, io) orelse @constCast(&.{});
        defer diskfree.mounts.freeAll(gpa, mnts);
        for (mnts) |m| {
            const u = diskfree.statfs.query(m.mount_point) catch continue;
            if (u.blocks_total == 0) continue; // dummy fs -- nothing to show
            try printMarginRow(out, m.mount_point, u);
        }
    }

    try out.flush();
    return 0;
}

fn printMarginRow(out: *std.Io.Writer, label: []const u8, u: diskfree.Usage) !void {
    const free_1k = u.freeBytes() / 1024;
    const avail_1k = u.availableBytes() / 1024;
    const margin = if (free_1k >= avail_1k) free_1k - avail_1k else 0;
    try out.print("{s:<16} {d:>12} {d:>12} {d:>10} 0x{x}\n", .{ label, free_1k, avail_1k, margin, u.fs_type_magic });
}

// ─────────────────────────────────────────────────────────────────────────────
// --mounts -- the mtab-shaped four-column table
// ─────────────────────────────────────────────────────────────────────────────

fn runMounts(gpa: Allocator, io: std.Io) !u8 {
    const mnts = try diskfree.mounts.readMounts(gpa, io) orelse @constCast(&.{});
    defer diskfree.mounts.freeAll(gpa, mnts);

    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;

    try out.print("{s:<20} {s:<28} {s:<10} {s}\n", .{ "Device", "Mounted on", "Type", "Options" });
    for (mnts) |m| {
        try out.print("{s:<20} {s:<28} {s:<10} {s}\n", .{ m.device, m.mount_point, m.fs_type, m.options });
    }
    try out.print(
        \\
        \\-- {d} row(s). This is the flat mtab(5) shape: no mount ID, no parent, no
        \\   propagation state. Run with --mountinfo for the richer source that has
        \\   all three.
        \\
    , .{mnts.len});
    try out.flush();
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// --mountinfo -- the richer source, propagation column included
// ─────────────────────────────────────────────────────────────────────────────

fn runMountinfo(gpa: Allocator, io: std.Io) !u8 {
    const mnts = try diskfree.mountinfo.readMountinfo(gpa, io) orelse @constCast(&.{});
    defer diskfree.mountinfo.freeAll(gpa, mnts);

    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;

    try out.print("{s:>5} {s:>6} {s:>8} {s:<28} {s:<10} {s}\n", .{ "ID", "Parent", "Maj:Min", "Mounted on", "Type", "Propagation" });
    var with_propagation: usize = 0;
    for (mnts) |m| {
        var mm_buf: [16]u8 = undefined;
        const mm = std.fmt.bufPrint(&mm_buf, "{d}:{d}", .{ m.dev_major, m.dev_minor }) catch "?";
        const prop = if (m.optional_fields.len > 0) m.optional_fields else "(none)";
        if (m.optional_fields.len > 0) with_propagation += 1;
        try out.print("{d:>5} {d:>6} {s:>8} {s:<28} {s:<10} {s}\n", .{ m.mount_id, m.parent_id, mm, m.mount_point, m.fs_type, prop });
    }
    try out.print(
        \\
        \\-- {d} row(s), {d} carrying a propagation/peer-group tag
        \\   (shared:N / master:N / propagate_from:N / unbindable) that the flat
        \\   `mounts`/`/proc/self/mounts` table (see --mounts) has no column for
        \\   at all -- those four columns simply cannot express it.
        \\
    , .{ mnts.len, with_propagation });
    try out.flush();
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// small helpers
// ─────────────────────────────────────────────────────────────────────────────

/// The `df`-vs-`du` warning, printed to STDERR deliberately: STDOUT stays a
/// clean table so it can be diffed byte-for-byte against real `df` output
/// without this banner's text getting in the way.
fn printBanner(io: std.Io) !void {
    try printErr(io, "{s}\n", .{not_du_banner});
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
