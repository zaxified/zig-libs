// SPDX-License-Identifier: MIT
const std = @import("std");

// tz-gen — parse IANA tzdata TZif files and emit modules/tz/src/tz_data.zig.
//
// Output = a compact, committed table: per-zone UTC-offset transitions from
// 1970 onward (the offset in effect at 1970 becomes the baseline `init_*`),
// plus each zone's POSIX-TZ footer for dates past the last transition. The
// generated file is the pin — regenerate when bumping the tzdata release.

const CUTOFF: i64 = 0; // 1970-01-01T00:00:00Z — drop pre-1970 history (baseline captured)

const Tr = struct { ts: i64, off: i32, dst: bool };

const ZoneOut = struct {
    name: []const u8,
    init_off: i32,
    init_dst: bool,
    trans: []const Tr,
    posix: []const u8,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // Args (0.16 removed argsAlloc; the runtime hands us a process.Args).
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    _ = it.next(); // exe name
    const out_path = try gpa.dupe(u8, it.next() orelse "../../modules/tz/src/tz_data.zig");
    defer gpa.free(out_path);
    const root_path = try gpa.dupe(u8, it.next() orelse "/usr/share/zoneinfo");
    defer gpa.free(root_path);
    it.deinit();

    var out_arena = std.heap.ArenaAllocator.init(gpa);
    defer out_arena.deinit();
    const oa = out_arena.allocator();

    var parse_arena = std.heap.ArenaAllocator.init(gpa);
    defer parse_arena.deinit();

    var root = try std.Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);

    const version = readVersion(gpa, io, root) catch "unknown";
    defer if (!std.mem.eql(u8, version, "unknown")) gpa.free(version);

    var zones: std.ArrayList(ZoneOut) = .empty;
    defer zones.deinit(gpa);

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

        _ = parse_arena.reset(.retain_capacity);
        const pa = parse_arena.allocator();

        var file = root.openFile(io, entry.path, .{}) catch continue;
        defer file.close(io);
        var rbuf: [64 * 1024]u8 = undefined;
        var freader = file.reader(io, &rbuf);
        var tz = std.Tz.parse(pa, &freader.interface) catch continue; // non-TZif → skip

        // Baseline: the time type in effect at the 1970 cutoff.
        var init_off: i32 = if (tz.timetypes.len > 0) tz.timetypes[0].offset else 0;
        var init_dst: bool = if (tz.timetypes.len > 0) tz.timetypes[0].isDst() else false;
        for (tz.transitions) |t| {
            if (t.ts <= CUTOFF) {
                init_off = t.timetype.offset;
                init_dst = t.timetype.isDst();
            } else break;
        }

        // Keep transitions after the cutoff, collapsing no-op repeats.
        var list: std.ArrayList(Tr) = .empty;
        var cur_off = init_off;
        var cur_dst = init_dst;
        for (tz.transitions) |t| {
            if (t.ts <= CUTOFF) continue;
            const off = t.timetype.offset;
            const dst = t.timetype.isDst();
            if (off == cur_off and dst == cur_dst) continue; // redundant transition
            try list.append(oa, .{ .ts = t.ts, .off = off, .dst = dst });
            cur_off = off;
            cur_dst = dst;
        }

        const posix = if (tz.footer) |f| try oa.dupe(u8, f) else "";

        try zones.append(gpa, .{
            .name = try oa.dupe(u8, entry.path),
            .init_off = init_off,
            .init_dst = init_dst,
            .trans = try list.toOwnedSlice(oa),
            .posix = posix,
        });
    }

    std.mem.sort(ZoneOut, zones.items, {}, lessZoneName);

    try emit(gpa, io, out_path, version, zones.items);

    std.debug.print("tz-gen: {d} zones from tzdata {s} -> {s}\n", .{ zones.items.len, version, out_path });
}

fn lessZoneName(_: void, a: ZoneOut, b: ZoneOut) bool {
    return std.mem.lessThan(u8, a.name, b.name);
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

fn emit(gpa: std.mem.Allocator, io: std.Io, out_path: []const u8, version: []const u8, zones: []const ZoneOut) !void {
    var out_file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
    defer out_file.close(io);
    var wbuf: [128 * 1024]u8 = undefined;
    var fw = out_file.writer(io, &wbuf);
    const w = &fw.interface;

    try w.print(
        \\// SPDX-License-Identifier: MIT
        \\// GENERATED by scripts/tz-gen from IANA tzdata {s} (public domain). DO NOT EDIT.
        \\// Regenerate: cd scripts/tz-gen && zig build run
        \\//
        \\// Per-zone UTC-offset transitions from 1970 onward (`init_off`/`init_dst`
        \\// is the offset in effect at the epoch). `posix` is the zone's POSIX-TZ
        \\// footer rule, applied for instants after the last explicit transition.
        \\
        \\pub const Transition = struct {{ ts: i64, off: i32, dst: bool }};
        \\
        \\pub const Zone = struct {{
        \\    name: []const u8,
        \\    init_off: i32,
        \\    init_dst: bool,
        \\    trans: []const Transition,
        \\    posix: []const u8,
        \\}};
        \\
        \\
    , .{version});

    // Dedup transition arrays by content: many Links share identical data.
    var dedup: std.StringHashMap(usize) = .init(gpa);
    defer {
        var it = dedup.keyIterator();
        while (it.next()) |k| gpa.free(k.*);
        dedup.deinit();
    }
    // sym[i] = the emitted symbol index for zone i's trans ("" if empty/inline).
    const syms = try gpa.alloc(?usize, zones.len);
    defer gpa.free(syms);

    var next_sym: usize = 0;
    for (zones, 0..) |z, i| {
        if (z.trans.len == 0) {
            syms[i] = null;
            continue;
        }
        const key = std.mem.sliceAsBytes(z.trans);
        if (dedup.get(key)) |idx| {
            syms[i] = idx;
            continue;
        }
        const idx = next_sym;
        next_sym += 1;
        syms[i] = idx;
        try dedup.put(try gpa.dupe(u8, key), idx);
        try emitTransArray(w, idx, z.trans);
    }

    try w.writeAll("pub const zones = [_]Zone{\n");
    for (zones, 0..) |z, i| {
        try w.writeAll("    .{ .name = ");
        try emitStr(w, z.name);
        try w.print(", .init_off = {d}, .init_dst = {}, .trans = ", .{ z.init_off, z.init_dst });
        if (syms[i]) |idx| {
            try w.print("&t{d}", .{idx});
        } else {
            try w.writeAll("&[_]Transition{}");
        }
        try w.writeAll(", .posix = ");
        try emitStr(w, z.posix);
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n");
    try w.flush();
}

fn emitTransArray(w: *std.Io.Writer, idx: usize, trans: []const Tr) !void {
    try w.print("const t{d} = [_]Transition{{\n", .{idx});
    var col: usize = 0;
    for (trans) |t| {
        if (col == 0) try w.writeAll("    ");
        try w.print(".{{ .ts = {d}, .off = {d}, .dst = {} }}, ", .{ t.ts, t.off, t.dst });
        col += 1;
        if (col == 4) {
            try w.writeAll("\n");
            col = 0;
        }
    }
    if (col != 0) try w.writeAll("\n");
    try w.writeAll("};\n");
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
