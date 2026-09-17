// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: one binary with the questions the suite cannot ask, because
// each needs either a foreign oracle, a size no test should pay for, or a
// measurement rather than an assertion.
//
//   file      one document's verdict (drives differ.sh)
//   ratio     input bytes -> PEAK LIVE bytes (audit F2 lived here)
//   depth     parse deep, then walk with the PUBLIC reading APIs (audit F5)
//   nsaxis    cost of inScopeNamespaces at a leaf
//   nsaxis_all the shape c14n really performs: once per element
//   nswide    depth x k declarations, ONE axis call at the apex (audit F1)
//   throughput MB/s on a real document
//   attrscan  is decodeReference's whole-source ';' search quadratic?
//   content   dump text/cdata/comment/PI bytes as hex (audit F3 lived here)
//   lookup    findByAttr / getElementById on one document
//
// ⚠ USE A REAL BACKING ALLOCATOR. The audit measured 16 MB/s before noticing it
// was running on `DebugAllocator`; the same parse is ~124 MB/s on
// `smp_allocator`. `ratio` deliberately measures against `page_allocator`,
// because that is the allocator the module's own documented table was produced
// with -- switching it changes the answer by 50 %.
//
// ⚠ `ratio` reports PEAK LIVE bytes, not cumulative. A cumulative counter
// cannot see simultaneity, and the bound that matters is the high-water mark.
//
// ⚠ NO ACCESS TO THE xmlconf VECTOR LIST, DELIBERATELY. The audit's probe had
// `vectors` and `dump` commands reading `xmlconf_vectors.zig` directly. That
// cannot be rebuilt as a separate module: `root.zig` already reaches that file
// through `xmlconf_test.zig`, and Zig refuses a file that belongs to two
// modules ("file exists in modules 'xmlvectors' and 'xml'"). The only way back
// would be to add public API to the module so a TOOL can see its fixtures --
// and a verification instrument must not reshape the thing it verifies. The
// loss is small: `xmlconf_test.zig` already drives all 130 vectors in-tree,
// both directions, with a canary test pinning the counts.
//
// WHAT IT NEEDS: the live module, nothing else.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseFast --dep xml \
//       -Mmain=probe.zig -Mxml=../src/root.zig \
//       --cache-dir <scratch>/zc-probe -femit-bin=<scratch>/probe

const std = @import("std");
const xml = @import("xml");

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// Peak-live-bytes allocator. `live` is what is currently held; `peak` its
/// high-water mark; `total` the cumulative sum, reported only for contrast.
const Tracking = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    peak: usize = 0,
    total: usize = 0,
    n_alloc: usize = 0,

    fn allocator(self: *Tracking) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }
    fn bump(self: *Tracking) void {
        if (self.live > self.peak) self.peak = self.live;
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Tracking = @ptrCast(@alignCast(ctx));
        const p = self.child.rawAlloc(len, a, ra) orelse return null;
        self.live += len;
        self.total += len;
        self.n_alloc += 1;
        self.bump();
        return p;
    }
    fn resize(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *Tracking = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(buf, a, new_len, ra)) return false;
        self.live = self.live - buf.len + new_len;
        if (new_len > buf.len) self.total += new_len - buf.len;
        self.bump();
        return true;
    }
    fn remap(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Tracking = @ptrCast(@alignCast(ctx));
        const p = self.child.rawRemap(buf, a, new_len, ra) orelse return null;
        self.live = self.live - buf.len + new_len;
        if (new_len > buf.len) self.total += new_len - buf.len;
        self.n_alloc += 1;
        self.bump();
        return p;
    }
    fn free(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *Tracking = @ptrCast(@alignCast(ctx));
        self.child.rawFree(buf, a, ra);
        self.live -= buf.len;
    }
};

fn dumpEl(el: *const xml.Element, d: usize) void {
    for (0..d) |_| std.debug.print("  ", .{});
    std.debug.print("<{s}> uri=\"{s}\"", .{ el.local, el.uri });
    for (el.attributes) |a| std.debug.print(" attr[{s}|{s}]={x}", .{ a.uri, a.local, a.value });
    std.debug.print("\n", .{});
    for (el.children) |c| switch (c.content) {
        .element => |e| dumpEl(e, d + 1),
        .text => |t| {
            for (0..d + 1) |_| std.debug.print("  ", .{});
            std.debug.print("text={x}\n", .{t});
        },
        .cdata => |t| {
            for (0..d + 1) |_| std.debug.print("  ", .{});
            std.debug.print("cdata={x}\n", .{t});
        },
        .comment => |t| {
            for (0..d + 1) |_| std.debug.print("  ", .{});
            std.debug.print("comment={x}\n", .{t});
        },
        .pi => |t| {
            for (0..d + 1) |_| std.debug.print("  ", .{});
            std.debug.print("pi target={s} data={x}\n", .{ t.target, t.data });
        },
    };
}

fn verdict(gpa: std.mem.Allocator, src: []const u8, opts: xml.Options) []const u8 {
    var doc = xml.parse(gpa, src, opts) catch |e| return @errorName(e);
    doc.deinit();
    return "OK";
}

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.smp_allocator;
    var argl: std.ArrayList([]const u8) = .empty;
    defer argl.deinit(gpa);
    const io = init.io;
    var it = init.minimal.args.iterate();
    while (it.next()) |a| try argl.append(gpa, a);
    const args = argl.items;
    if (args.len < 2) {
        std.debug.print("usage: probe <cmd> [args]\n", .{});
        return;
    }
    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "file")) {
        const path = args[2];
        const ignore = args.len > 3 and std.mem.eql(u8, args[3], "ignore");
        const src = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 28));
        defer gpa.free(src);
        const opts: xml.Options = .{ .doctype = if (ignore) .ignore else .reject };
        std.debug.print("{s}\n", .{verdict(gpa, src, opts)});
        return;
    }

    if (std.mem.eql(u8, cmd, "ratio")) {
        const path = args[2];
        const ignore = args.len > 3 and std.mem.eql(u8, args[3], "ignore");
        const src = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 28));
        defer gpa.free(src);
        // ⚠ page_allocator on purpose: the module's own documented table was
        // produced against it. DebugAllocator gives ~1.5x the peak for the same
        // input, so comparing to the doc on a different backing is comparing
        // two different quantities.
        var tr: Tracking = .{ .child = std.heap.page_allocator };
        const a = tr.allocator();
        const opts: xml.Options = .{ .doctype = if (ignore) .ignore else .reject };
        const t0 = nowNs();
        if (xml.parse(a, src, opts)) |d| {
            var doc = d;
            const t1 = nowNs();
            std.debug.print("in={d} peak_live={d} ratio={d:.2} total_alloc={d} n_alloc={d} ns={d} verdict=OK\n", .{ src.len, tr.peak, @as(f64, @floatFromInt(tr.peak)) / @as(f64, @floatFromInt(src.len)), tr.total, tr.n_alloc, t1 - t0 });
            doc.deinit();
            return;
        } else |e| {
            const t1 = nowNs();
            std.debug.print("in={d} peak_live={d} ratio={d:.2} total_alloc={d} n_alloc={d} ns={d} verdict={s}\n", .{ src.len, tr.peak, @as(f64, @floatFromInt(tr.peak)) / @as(f64, @floatFromInt(src.len)), tr.total, tr.n_alloc, t1 - t0, @errorName(e) });
            return;
        }
    }

    if (std.mem.eql(u8, cmd, "depth")) {
        // Parse an n-deep document, then walk it with the PUBLIC reading APIs.
        // ⚠ `findByAttr` takes an allocator and returns an error union since
        // audit F5-zbytek replaced its machine recursion with a heap stack --
        // the old signature is what this probe used to call.
        const n = try std.fmt.parseInt(usize, args[2], 10);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        for (0..n) |_| try buf.appendSlice(gpa, "<e>");
        try buf.appendSlice(gpa, "<leaf ID=\"z\">x</leaf>");
        for (0..n) |_| try buf.appendSlice(gpa, "</e>");
        std.debug.print("depth={d} src={d}B ", .{ n, buf.items.len });
        var doc = xml.parse(gpa, buf.items, .{ .max_depth = n + 2, .max_elements = 1 << 30 }) catch |e| {
            std.debug.print("parse={s}\n", .{@errorName(e)});
            return;
        };
        defer doc.deinit();
        std.debug.print("parse=OK ", .{});
        const t = try doc.findByAttr(gpa, "", "ID", "z");
        std.debug.print("findByAttr={s} ", .{if (t != null) "found" else "null"});
        const txt = try doc.root.textContent(gpa);
        defer gpa.free(txt);
        std.debug.print("textContent={d}B OK\n", .{txt.len});
        return;
    }

    if (std.mem.eql(u8, cmd, "nsaxis")) {
        const n = try std.fmt.parseInt(usize, args[2], 10);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        for (0..n) |i| try buf.print(gpa, "<e xmlns:p{d}=\"urn:{d}\">", .{ i, i });
        try buf.appendSlice(gpa, "<leaf/>");
        for (0..n) |_| try buf.appendSlice(gpa, "</e>");
        var doc = try xml.parse(gpa, buf.items, .{ .max_depth = n + 2, .max_elements = 1 << 30 });
        defer doc.deinit();
        var leaf: *const xml.Element = doc.root;
        while (leaf.firstElementChild()) |c| leaf = c;
        const t0 = nowNs();
        const axis = try leaf.inScopeNamespaces(gpa);
        const t1 = nowNs();
        defer gpa.free(axis);
        std.debug.print("nsaxis depth={d} src={d}B decls={d} ns={d}\n", .{ n, buf.items.len, axis.len, t1 - t0 });
        return;
    }

    if (std.mem.eql(u8, cmd, "nsaxis_all")) {
        const n = try std.fmt.parseInt(usize, args[2], 10);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        for (0..n) |i| try buf.print(gpa, "<e xmlns:p{d}=\"urn:{d}\">", .{ i, i });
        for (0..n) |_| try buf.appendSlice(gpa, "</e>");
        var doc = try xml.parse(gpa, buf.items, .{ .max_depth = n + 2, .max_elements = 1 << 30 });
        defer doc.deinit();
        const t0 = nowNs();
        var total: usize = 0;
        var cur: ?*const xml.Element = doc.root;
        while (cur) |el| {
            const axis = try el.inScopeNamespaces(gpa);
            total += axis.len;
            gpa.free(axis);
            cur = el.firstElementChild();
        }
        const t1 = nowNs();
        std.debug.print("nsaxis_all depth={d} src={d}B sum_decls={d} ns={d}\n", .{ n, buf.items.len, total, t1 - t0 });
        return;
    }

    if (std.mem.eql(u8, cmd, "throughput")) {
        const path = args[2];
        const iters = try std.fmt.parseInt(usize, args[3], 10);
        const src = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 28));
        defer gpa.free(src);
        var best: u64 = std.math.maxInt(u64);
        var sum: u64 = 0;
        for (0..iters) |_| {
            const t0 = nowNs();
            var doc = try xml.parse(gpa, src, .{ .max_elements = 1 << 30, .max_depth = 1 << 20 });
            const t1 = nowNs();
            doc.deinit();
            const d = t1 - t0;
            if (d < best) best = d;
            sum += d;
        }
        const mbps = @as(f64, @floatFromInt(src.len)) * 1000.0 / @as(f64, @floatFromInt(best));
        std.debug.print("src={d}B iters={d} best_ns={d} mean_ns={d} best_MBps={d:.1}\n", .{ src.len, iters, best, sum / iters, mbps });
        return;
    }

    if (std.mem.eql(u8, cmd, "attrscan")) {
        const n = try std.fmt.parseInt(usize, args[2], 10);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try buf.appendSlice(gpa, "<a>");
        for (0..n) |_| try buf.appendSlice(gpa, "&amp;");
        try buf.appendSlice(gpa, "</a>");
        const t0 = nowNs();
        var doc = try xml.parse(gpa, buf.items, .{});
        const t1 = nowNs();
        doc.deinit();
        std.debug.print("amps={d} src={d}B ns={d}\n", .{ n, buf.items.len, t1 - t0 });
        return;
    }

    if (std.mem.eql(u8, cmd, "nswide")) {
        // `depth` nested elements, each declaring `k` namespaces, then ONE
        // inScopeNamespaces call at the apex -- the exact shape xmldsig's
        // inclusive C14N performs, and where audit F1's quadratic lived.
        const depth = try std.fmt.parseInt(usize, args[2], 10);
        const k = try std.fmt.parseInt(usize, args[3], 10);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        for (0..depth) |lvl| {
            try buf.print(gpa, "<e{d}", .{lvl});
            for (0..k) |i| try buf.print(gpa, " xmlns:p{d}_{d}=\"urn:{d}:{d}\"", .{ lvl, i, lvl, i });
            try buf.appendSlice(gpa, ">");
        }
        try buf.appendSlice(gpa, "<apex/>");
        var lvl = depth;
        while (lvl > 0) : (lvl -= 1) try buf.print(gpa, "</e{d}>", .{lvl - 1});
        const t0 = nowNs();
        var doc = try xml.parse(gpa, buf.items, .{});
        const t1 = nowNs();
        defer doc.deinit();
        var leaf: *const xml.Element = doc.root;
        while (leaf.firstElementChild()) |c| leaf = c;
        const t2 = nowNs();
        const axis = try leaf.inScopeNamespaces(gpa);
        const t3 = nowNs();
        defer gpa.free(axis);
        std.debug.print("nswide depth={d} k={d} src={d}B in_scope={d} parse_ns={d} axis_ns={d}\n", .{ depth, k, buf.items.len, axis.len, t1 - t0, t3 - t2 });
        return;
    }

    if (std.mem.eql(u8, cmd, "content")) {
        const path = args[2];
        const ignore = args.len > 3 and std.mem.eql(u8, args[3], "ignore");
        const src = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 28));
        defer gpa.free(src);
        var doc = xml.parse(gpa, src, .{ .doctype = if (ignore) .ignore else .reject }) catch |e| {
            std.debug.print("ERR {s}\n", .{@errorName(e)});
            return;
        };
        defer doc.deinit();
        dumpEl(doc.root, 0);
        return;
    }

    if (std.mem.eql(u8, cmd, "lookup")) {
        const src = try std.Io.Dir.cwd().readFileAlloc(io, args[2], gpa, .limited(1 << 28));
        defer gpa.free(src);
        var doc = try xml.parse(gpa, src, .{});
        defer doc.deinit();
        const uri = args[3];
        const local = args[4];
        const val = args[5];
        if (try doc.findByAttr(gpa, uri, local, val)) |el| {
            std.debug.print("findByAttr -> <{s}> span=[{d},{d}) bytes=\"{s}\"\n", .{ el.local, el.span.start, el.span.end, el.span.slice(src) });
        } else std.debug.print("findByAttr -> null\n", .{});
        if (doc.getElementById(val)) |el| {
            std.debug.print("getElementById -> <{s}> span=[{d},{d})\n", .{ el.local, el.span.start, el.span.end });
        } else std.debug.print("getElementById -> null\n", .{});
        return;
    }

    std.debug.print("unknown cmd {s}\n", .{cmd});
}
