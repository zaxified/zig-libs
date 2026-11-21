// SPDX-License-Identifier: MIT
const std = @import("std");
const posix = @import("posix");

// tz-gen — parse IANA tzdata TZif files and emit modules/tz/src/tz_data.zig
// (and, with a third argument, tz_data_full.zig).
//
// Output = a compact, committed table: per-zone UTC-offset/DST/abbreviation
// transitions from 1970 onward (the state in effect at 1970 becomes the
// baseline `init_*`), plus each zone's POSIX-TZ footer — as text and parsed
// (`posix.parse`, the same parser the module uses at run time) — for dates
// past the last transition. The `full` variant keeps the history before 1970
// (down to the first, local-mean-time state), as `Zone.pre`: tz_data_full.zig
// holds only those pre-1970 changes and the initial states, and takes every
// other field (including the 1970..2037 `trans` arrays) from tz_data.zig. The
// post-1970 changes are stored packed (`Compact`, 8 bytes). The generated
// files are the pin — regenerate when bumping the tzdata release.
//
// Checks that fail the run (a table that looks regenerated and is not is the
// failure this tool exists to prevent): every zone has a footer, every footer
// parses, every link target exists, no 4-day window holds more offset changes
// than the module's `Changes` buffer can take, the abbreviation table fits the
// 11-bit index of a `Compact`, every post-1970 change time fits a `u32`, and
// the full table's changes after the epoch are the default table's.

/// Default table: drop everything at or before the epoch (baseline captured).
const cutoff_default: i64 = 0;
/// Full table: zic -b fat starts with a "big bang" entry at -2^59; fold that
/// into the initial state and keep every real change.
const cutoff_full: i64 = -(1 << 50);

/// `max_changes` of modules/tz/src/root.zig is 32; a window (4 days) may also
/// hold up to 4 footer changes, so the explicit transitions must leave room.
const max_window_transitions = 12;
const window_secs: i64 = 4 * 86400;

const Tr = struct { ts: i64, off: i32, dst: bool, abbr: []const u8 };

const ZoneOut = struct {
    name: []const u8,
    init_off: i32,
    init_dst: bool,
    init_abbr: []const u8,
    trans: []const Tr,
    posix: []const u8,
    canonical: ?[]const u8,
};

const Raw = struct { name: []const u8, tz: std.Tz };

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // Args (0.16 removed argsAlloc; the runtime hands us a process.Args).
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    _ = it.next(); // exe name
    const out_path = try gpa.dupe(u8, it.next() orelse "../../../modules/tz/src/tz_data.zig");
    defer gpa.free(out_path);
    const root_path = try gpa.dupe(u8, it.next() orelse "/usr/share/zoneinfo");
    defer gpa.free(root_path);
    const full_path: ?[]const u8 = if (it.next()) |p| try gpa.dupe(u8, p) else null;
    defer if (full_path) |p| gpa.free(p);
    it.deinit();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var root = try std.Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);

    const version = readVersion(gpa, io, root) catch "unknown";
    defer if (!std.mem.eql(u8, version, "unknown")) gpa.free(version);

    var raws: std.ArrayList(Raw) = .empty;
    defer raws.deinit(gpa);

    var walker = try root.walk(gpa);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file and entry.kind != .sym_link) continue;
        // posix/ and right/ are alternate encodings (right/ folds leap seconds
        // into offsets, which would corrupt wall-clock math) — skip them.
        if (std.mem.startsWith(u8, entry.path, "posix/")) continue;
        if (std.mem.startsWith(u8, entry.path, "right/")) continue;

        // `localtime` and `posixrules` are installed by the OS, not shipped
        // by IANA: on a Debian/Ubuntu host `localtime` symlinks to
        // `/etc/localtime` -- the BUILD MACHINE's configured timezone -- and
        // `posixrules` to a legacy US-rules zone. Emitting them puts a
        // machine-specific value into a committed table under a name no
        // consumer should look up, and makes the output depend on who ran
        // this. Skipped by name because that is what they are: names, not a
        // directory prefix like the two above.
        if (std.mem.eql(u8, entry.path, "localtime")) continue;
        if (std.mem.eql(u8, entry.path, "posixrules")) continue;

        var file = root.openFile(io, entry.path, .{}) catch continue;
        defer file.close(io);
        var rbuf: [64 * 1024]u8 = undefined;
        var freader = file.reader(io, &rbuf);
        const tz = std.Tz.parse(arena, &freader.interface) catch continue; // non-TZif → skip
        try raws.append(gpa, .{ .name = try arena.dupe(u8, entry.path), .tz = tz });
    }

    std.mem.sort(Raw, raws.items, {}, lessRawName);

    const links = try readLinks(arena, io, root, raws.items);

    // Both variants share ONE abbreviation table (emitted in tz_data.zig,
    // imported by tz_data_full.zig), so a zone of either table resolves its
    // `abbr` indices the same way and `tz.full.find` zones go through every
    // function of the module. Default zones intern first, so the default
    // table's indices do not depend on the pre-1970 history.
    const zones_default = try buildZones(arena, raws.items, links, cutoff_default);
    const zones_full = try buildZones(arena, raws.items, links, cutoff_full);
    var abbrevs: Abbrevs = .{};
    for ([_][]const ZoneOut{ zones_default, zones_full }) |set| for (set) |z| {
        _ = try abbrevs.intern(arena, z.init_abbr);
        for (z.trans) |t| _ = try abbrevs.intern(arena, t.abbr);
    };

    try emit(gpa, io, out_path, version, zones_default, &abbrevs);
    std.debug.print("tz-gen: {d} zones from tzdata {s} -> {s}\n", .{ zones_default.len, version, out_path });
    if (full_path) |p| {
        try emitFull(gpa, io, p, version, zones_full, zones_default, &abbrevs);
        std.debug.print("tz-gen: {d} zones from tzdata {s} -> {s}\n", .{ zones_full.len, version, p });
    }
}

fn lessRawName(_: void, a: Raw, b: Raw) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

/// Link name → canonical zone name, from `+LINKS` (`<target> <link>` lines,
/// written by fetch-and-build.sh from the `Link` lines of the tzdata source
/// files: the compiled tree does not say which file is an alias). Chains are
/// followed to a name that is not itself a link. A link whose own file is not
/// in the tree is ignored; a target that is not in the tree is an error.
fn readLinks(arena: std.mem.Allocator, io: std.Io, root: std.Io.Dir, raws: []const Raw) !std.StringHashMapUnmanaged([]const u8) {
    const bytes = root.readFileAlloc(io, "+LINKS", arena, .limited(1 << 20)) catch |e| {
        std.debug.print("tz-gen: cannot read +LINKS from the zoneinfo tree ({t}); fetch-and-build.sh writes it\n", .{e});
        return error.NoLinks;
    };
    var direct: std.StringHashMapUnmanaged([]const u8) = .empty;
    var lines = std.mem.tokenizeScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const target = f.next() orelse continue;
        const link = f.next() orelse return error.BadLinksLine;
        try direct.put(arena, link, target);
    }
    var present: std.StringHashMapUnmanaged(void) = .empty;
    for (raws) |r| try present.put(arena, r.name, {});

    var resolved: std.StringHashMapUnmanaged([]const u8) = .empty;
    var kit = direct.iterator();
    while (kit.next()) |e| {
        if (!present.contains(e.key_ptr.*)) continue;
        var target = e.value_ptr.*;
        var hops: usize = 0;
        while (direct.get(target)) |next| : (hops += 1) {
            if (hops > 8) return error.LinkCycle;
            target = next;
        }
        if (!present.contains(target)) {
            std.debug.print("tz-gen: link {s} points to {s}, which is not in the tree\n", .{ e.key_ptr.*, target });
            return error.LinkTargetMissing;
        }
        try resolved.put(arena, e.key_ptr.*, target);
    }
    return resolved;
}

fn buildZones(
    arena: std.mem.Allocator,
    raws: []const Raw,
    links: std.StringHashMapUnmanaged([]const u8),
    cutoff: i64,
) ![]const ZoneOut {
    var zones: std.ArrayList(ZoneOut) = .empty;
    var max_window: usize = 0;
    for (raws) |r| {
        const tz = r.tz;
        // Baseline: the time type in effect at the cutoff.
        var init_name: []const u8 = if (tz.timetypes.len > 0) try arena.dupe(u8, tz.timetypes[0].name()) else "";
        var init_off: i32 = if (tz.timetypes.len > 0) tz.timetypes[0].offset else 0;
        var init_dst: bool = if (tz.timetypes.len > 0) tz.timetypes[0].isDst() else false;
        for (tz.transitions) |t| {
            if (t.ts <= cutoff) {
                init_off = t.timetype.offset;
                init_dst = t.timetype.isDst();
                init_name = try arena.dupe(u8, t.timetype.name());
            } else break;
        }

        // Keep transitions after the cutoff, collapsing no-op repeats.
        var list: std.ArrayList(Tr) = .empty;
        var cur_off = init_off;
        var cur_dst = init_dst;
        var cur_name = init_name;
        for (tz.transitions) |t| {
            if (t.ts <= cutoff) continue;
            const off = t.timetype.offset;
            const dst = t.timetype.isDst();
            const name = t.timetype.name();
            if (off == cur_off and dst == cur_dst and std.mem.eql(u8, name, cur_name)) continue; // redundant transition
            const owned = try arena.dupe(u8, name);
            try list.append(arena, .{ .ts = t.ts, .off = off, .dst = dst, .abbr = owned });
            cur_off = off;
            cur_dst = dst;
            cur_name = owned;
        }

        // No silent fallback: a zone without a footer that parses would make
        // `offsetAt` guess past its last transition.
        const footer = tz.footer orelse {
            std.debug.print("tz-gen: {s} has no POSIX footer\n", .{r.name});
            return error.MissingFooter;
        };
        if (posix.parse(footer) == null) {
            std.debug.print("tz-gen: {s}: footer \"{s}\" does not parse\n", .{ r.name, footer });
            return error.UnparsableFooter;
        }

        // `resolveLocal` collects the changes of a 4-day window into a fixed
        // buffer: bound what a window can hold.
        const trs = list.items;
        var lo: usize = 0;
        for (trs, 0..) |t, hi| {
            while (trs[lo].ts < t.ts - window_secs) lo += 1;
            max_window = @max(max_window, hi - lo + 1);
            if (hi - lo + 1 > max_window_transitions) {
                std.debug.print("tz-gen: {s}: {d} transitions within 4 days of {d}\n", .{ r.name, hi - lo + 1, t.ts });
                return error.TooManyTransitionsInWindow;
            }
        }

        try zones.append(arena, .{
            .name = r.name,
            .init_off = init_off,
            .init_dst = init_dst,
            .init_abbr = init_name,
            .trans = trs,
            .posix = try arena.dupe(u8, footer),
            .canonical = links.get(r.name),
        });
    }
    std.debug.print("tz-gen: most transitions in any 4-day window: {d} (limit {d})\n", .{ max_window, max_window_transitions });
    return zones.items;
}

fn readVersion(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir) ![]const u8 {
    // tzdata.zi starts with a "# version <rel>" line.
    // tzdata.zi is the full zic source (~1 MB); we only read its first line.
    const bytes = root.readFileAlloc(io, "tzdata.zi", gpa, .limited(4 << 20)) catch {
        // `+VERSION` is the whole file, and it ends with a newline. Left in,
        // it lands mid-sentence in the generated header comment and breaks
        // the line -- which is how it was found.
        const raw = root.readFileAlloc(io, "+VERSION", gpa, .limited(64)) catch return error.NoVersion;
        defer gpa.free(raw);
        return gpa.dupe(u8, std.mem.trim(u8, raw, " \t\r\n"));
    };
    defer gpa.free(bytes);
    var it = std.mem.tokenizeAny(u8, bytes, " \n\r");
    _ = it.next(); // "#"
    _ = it.next(); // "version"
    const v = it.next() orelse return error.NoVersion;
    return gpa.dupe(u8, v);
}

/// Distinct abbreviations in first-use order, as one NUL-separated string
/// whose first byte is a NUL (offset 0 = the empty string).
const Abbrevs = struct {
    blob: std.ArrayList(u8) = .empty,
    index: std.StringHashMapUnmanaged(u16) = .empty,

    fn intern(a: *Abbrevs, gpa: std.mem.Allocator, name: []const u8) !u16 {
        if (a.blob.items.len == 0) try a.blob.append(gpa, 0);
        if (name.len == 0) return 0;
        if (a.index.get(name)) |i| return i;
        const at = a.blob.items.len;
        if (at > std.math.maxInt(u16)) return error.AbbrevTableTooLarge;
        try a.blob.appendSlice(gpa, name);
        try a.blob.append(gpa, 0);
        const key = try gpa.dupe(u8, name);
        try a.index.put(gpa, key, @intCast(at));
        return @intCast(at);
    }
};

/// `types.Compact`'s bounds, checked here so the generated `make` calls cannot fail to compile.
const compact_max_abbr: u16 = 2047;
const compact_off_limit: i32 = 1 << 19;

fn emit(gpa: std.mem.Allocator, io: std.Io, out_path: []const u8, version: []const u8, zones: []const ZoneOut, abbrevs: *const Abbrevs) !void {
    var out_file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
    defer out_file.close(io);
    var wbuf: [128 * 1024]u8 = undefined;
    var fw = out_file.writer(io, &wbuf);
    const w = &fw.interface;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try w.print(
        \\// SPDX-License-Identifier: MIT
        \\// GENERATED by scripts/gen/tz-gen from IANA tzdata {s} (public domain). DO NOT EDIT.
        \\// Regenerate: scripts/gen/tz-gen/fetch-and-build.sh
        \\//
        \\
    , .{version});
    try w.writeAll(
        \\// Per-zone UTC-offset/DST/abbreviation transitions from 1970 onward
        \\// (`init_*` is the state in effect at the epoch; earlier history is folded
        \\// into it -- `tz_data_full.zig` keeps it), in the packed 8-byte form
        \\// (`Compact`: `c(ts, off, dst, abbr)`).
        \\// `posix` is the zone's POSIX-TZ footer rule, applied for instants after the
        \\// last explicit transition; `footer` is the same rule parsed at generation
        \\// time. `abbr`/`init_abbr` are byte offsets into `abbrevs` (one table for
        \\// both variants, defined in tz_data.zig).
        \\
        \\const types = @import("types.zig");
        \\pub const Transition = types.Transition;
        \\pub const Compact = types.Compact;
        \\pub const Zone = types.Zone;
        \\const Footer = types.Footer;
        \\const c = Compact.make;
        \\
        \\
    );

    try w.writeAll("/// NUL-terminated abbreviations; offset 0 is the empty string.\n");
    try w.writeAll("pub const abbrevs: []const u8 =\n");
    {
        // One literal per abbreviation, a few per line.
        var col: usize = 0;
        try w.writeAll("    \"\\x00\"");
        var at: usize = 1;
        while (at < abbrevs.blob.items.len) {
            const end = std.mem.findScalarPos(u8, abbrevs.blob.items, at, 0).?;
            if (col % 8 == 7) try w.writeAll("\n    ++ ") else try w.writeAll(" ++ ");
            try w.print("\"{s}\\x00\"", .{abbrevs.blob.items[at..end]});
            col += 1;
            at = end + 1;
        }
        try w.writeAll(";\n\n");
    }

    // Footers, deduplicated by their text.
    var footer_idx: std.StringHashMapUnmanaged(usize) = .empty;
    var next_footer: usize = 0;
    const footer_of = try arena.alloc(usize, zones.len);
    for (zones, 0..) |z, i| {
        if (footer_idx.get(z.posix)) |idx| {
            footer_of[i] = idx;
            continue;
        }
        const f = posix.parse(z.posix).?;
        const idx = next_footer;
        next_footer += 1;
        try footer_idx.put(arena, z.posix, idx);
        footer_of[i] = idx;
        try w.print("const ft{d}: Footer = .{{ .std_abbr = \"{s}\", .utc_std = {d}, .dst = ", .{ idx, f.std_abbr, f.utc_std });
        if (f.dst) |d| {
            try w.print(".{{ .abbr = \"{s}\", .utc_dst = {d}, .start = ", .{ d.abbr, d.utc_dst });
            try emitRule(w, d.start);
            try w.print(", .start_time = {d}, .end = ", .{d.start_time});
            try emitRule(w, d.end);
            try w.print(", .end_time = {d} }}", .{d.end_time});
        } else try w.writeAll("null");
        try w.writeAll(" };\n");
    }
    try w.writeAll("\n");

    // Dedup transition arrays by their emitted text: many Links share identical data.
    var dedup: std.StringHashMapUnmanaged(usize) = .empty;
    // sym[i] = the emitted symbol index for zone i's trans (null if empty/inline).
    const syms = try arena.alloc(?usize, zones.len);
    var next_sym: usize = 0;
    for (zones, 0..) |z, i| {
        if (z.trans.len == 0) {
            syms[i] = null;
            continue;
        }
        var text: std.Io.Writer.Allocating = .init(arena);
        try emitCompactBody(&text.writer, abbrevs, z.name, z.trans);
        const key = text.written();
        if (dedup.get(key)) |idx| {
            syms[i] = idx;
            continue;
        }
        const idx = next_sym;
        next_sym += 1;
        syms[i] = idx;
        try dedup.put(arena, key, idx);
        try w.print("const t{d} = [_]Compact{{\n{s}}};\n", .{ idx, key });
    }

    try w.writeAll("pub const zones = [_]Zone{\n");
    for (zones, 0..) |z, i| {
        try w.writeAll("    .{ .name = ");
        try emitStr(w, z.name);
        try w.print(", .init_off = {d}, .init_dst = {}, .init_abbr = {d}, .trans = ", .{ z.init_off, z.init_dst, abbrevs.index.get(z.init_abbr) orelse 0 });
        if (syms[i]) |idx| {
            try w.print("&t{d}", .{idx});
        } else {
            try w.writeAll("&.{}");
        }
        try w.writeAll(", .posix = ");
        try emitStr(w, z.posix);
        try w.print(", .footer = &ft{d}", .{footer_of[i]});
        if (z.canonical) |cn| {
            try w.writeAll(", .canonical = ");
            try emitStr(w, cn);
        }
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n");
    try w.flush();
}

/// tz_data_full.zig: per zone the initial (local mean time) state and the
/// changes up to the epoch (`pre`); everything else, `trans` included, is the
/// default table's zone. The changes after the epoch must be the default
/// table's, or the two tables would disagree.
fn emitFull(
    gpa: std.mem.Allocator,
    io: std.Io,
    out_path: []const u8,
    version: []const u8,
    full: []const ZoneOut,
    default: []const ZoneOut,
    abbrevs: *const Abbrevs,
) !void {
    if (full.len != default.len) return error.TablesDiffer;
    var out_file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
    defer out_file.close(io);
    var wbuf: [128 * 1024]u8 = undefined;
    var fw = out_file.writer(io, &wbuf);
    const w = &fw.interface;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try w.print(
        \\// SPDX-License-Identifier: MIT
        \\// GENERATED by scripts/gen/tz-gen from IANA tzdata {s} (public domain). DO NOT EDIT.
        \\// Regenerate: scripts/gen/tz-gen/fetch-and-build.sh
        \\//
        \\// FULL variant: every offset/DST/abbreviation change zic emits, back to the
        \\// zone's first (local mean time) state, which is `init_*`. Reached through
        \\// `tz.full`; compiled only into a program that uses it. Per zone this file
        \\// holds only that state and the changes up to the epoch (`pre`); every other
        \\// field, the 1970..2037 `trans` array included, is the zone of tz_data.zig.
        \\// `abbr`/`init_abbr` are byte offsets into the shared `abbrevs`.
        \\
        \\const types = @import("types.zig");
        \\const default = @import("tz_data.zig");
        \\const Transition = types.Transition;
        \\
        \\/// The shared abbreviation table (tz_data.zig).
        \\pub const abbrevs = default.abbrevs;
        \\
        \\
    , .{version});

    var dedup: std.StringHashMapUnmanaged(usize) = .empty;
    const syms = try arena.alloc(?usize, full.len);
    var next_sym: usize = 0;
    for (full, default, 0..) |z, d, i| {
        if (!std.mem.eql(u8, z.name, d.name) or !std.mem.eql(u8, z.posix, d.posix)) return error.TablesDiffer;
        // Split at the epoch; the part after it is the default table's list.
        var n_pre: usize = 0;
        while (n_pre < z.trans.len and z.trans[n_pre].ts <= cutoff_default) n_pre += 1;
        const post = z.trans[n_pre..];
        if (post.len != d.trans.len) {
            std.debug.print("tz-gen: {s}: full table has {d} changes after the epoch, default {d}\n", .{ z.name, post.len, d.trans.len });
            return error.TablesDiffer;
        }
        for (post, d.trans) |a, b| {
            if (a.ts != b.ts or a.off != b.off or a.dst != b.dst or !std.mem.eql(u8, a.abbr, b.abbr)) {
                std.debug.print("tz-gen: {s}: change at {d} differs between the tables\n", .{ z.name, a.ts });
                return error.TablesDiffer;
            }
        }
        if (n_pre == 0) {
            syms[i] = null;
            continue;
        }
        var text: std.Io.Writer.Allocating = .init(arena);
        try emitTransBody(&text.writer, abbrevs, z.trans[0..n_pre]);
        const key = text.written();
        if (dedup.get(key)) |idx| {
            syms[i] = idx;
            continue;
        }
        const idx = next_sym;
        next_sym += 1;
        syms[i] = idx;
        try dedup.put(arena, key, idx);
        try w.print("const p{d} = [_]Transition{{\n{s}}};\n", .{ idx, key });
    }

    try w.writeAll(
        \\
        \\const Over = struct { init_off: i32, init_dst: bool, init_abbr: u16, pre: []const Transition };
        \\const over = [_]Over{
        \\
    );
    for (full, 0..) |z, i| {
        try w.print("    .{{ .init_off = {d}, .init_dst = {}, .init_abbr = {d}, .pre = ", .{ z.init_off, z.init_dst, abbrevs.index.get(z.init_abbr) orelse 0 });
        if (syms[i]) |idx| try w.print("&p{d}", .{idx}) else try w.writeAll("&.{}");
        try w.writeAll(" },\n");
    }
    try w.writeAll(
        \\};
        \\
        \\pub const zones = blk: {
        \\    @setEvalBranchQuota(20_000);
        \\    var z = default.zones;
        \\    for (&z, over) |*e, o| {
        \\        e.init_off = o.init_off;
        \\        e.init_dst = o.init_dst;
        \\        e.init_abbr = o.init_abbr;
        \\        e.pre = o.pre;
        \\    }
        \\    const done = z;
        \\    break :blk done;
        \\};
        \\
    );
    try w.flush();
}

fn emitRule(w: *std.Io.Writer, r: posix.Rule) !void {
    switch (r) {
        .mwd => |m| try w.print(".{{ .mwd = .{{ .month = {d}, .week = {d}, .day = {d} }} }}", .{ m.month, m.week, m.day }),
        .julian => |n| try w.print(".{{ .julian = {d} }}", .{n}),
        .yday => |n| try w.print(".{{ .yday = {d} }}", .{n}),
    }
}

fn emitTransBody(w: *std.Io.Writer, abbrevs: *const Abbrevs, trans: []const Tr) !void {
    var col: usize = 0;
    for (trans) |t| {
        if (col == 0) try w.writeAll("    ");
        const a = abbrevs.index.get(t.abbr) orelse 0;
        try w.print(".{{ .ts = {d}, .off = {d}, .dst = {}, .abbr = {d} }}, ", .{ t.ts, t.off, t.dst, a });
        col += 1;
        if (col == 4) {
            try w.writeAll("\n");
            col = 0;
        }
    }
    if (col != 0) try w.writeAll("\n");
}

/// `trans` as `c(ts, off, dst, abbr)` calls, four per line. Refuses what a
/// `Compact` cannot hold: a time outside `i32`, an offset beyond 20 bits, an
/// abbreviation index past 11 bits.
fn emitCompactBody(w: *std.Io.Writer, abbrevs: *const Abbrevs, zone: []const u8, trans: []const Tr) !void {
    var col: usize = 0;
    for (trans) |t| {
        const ts = std.math.cast(u32, t.ts) orelse {
            std.debug.print("tz-gen: {s}: change at {d} does not fit a u32\n", .{ zone, t.ts });
            return error.TransitionBeyondU32;
        };
        const a = abbrevs.index.get(t.abbr) orelse 0;
        if (a > compact_max_abbr or t.off < -compact_off_limit or t.off >= compact_off_limit) {
            std.debug.print("tz-gen: {s}: change at {d} does not fit a Compact (abbr {d}, off {d})\n", .{ zone, t.ts, a, t.off });
            return error.TransitionNotCompact;
        }
        if (col == 0) try w.writeAll("    ");
        try w.print("c({d}, {d}, {}, {d}), ", .{ ts, t.off, t.dst, a });
        col += 1;
        if (col == 4) {
            try w.writeAll("\n");
            col = 0;
        }
    }
    if (col != 0) try w.writeAll("\n");
}

fn emitStr(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"', '\\' => try w.print("\\{c}", .{c}),
            '\n' => try w.writeAll("\\n"),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}
