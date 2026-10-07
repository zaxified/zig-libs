// SPDX-License-Identifier: MIT

//! Comparative benchmark: `netaddr` against Go's `net/netip` and
//! go4.org/netipx (the reference), the program behind the `**Performance:**`
//! line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-netaddr` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! go4.org/netipx in the module cache (pinned by `tools/go_bench/go.mod`, the
//! same version the netip oracle pins; `GOPROXY=off`). Run from the repository
//! root.
//!
//! Inputs are generated here from fixed seeds and written as text into
//! `.zig-cache/bench-netaddr/`; both sides read the same lines. One op = one
//! pass over a list of 1,000 inputs (200 prefixes for `set_build`). Both sides
//! double the batch until it takes over 100 ms and keep the best of five; each
//! reports a result count, and a count that differs fails the run. The verdict
//! is the WORST ratio, ours/Go.

const std = @import("std");
const netaddr = @import("netaddr");

const n_inputs = 1000;
const n_set = 200;
const work_dir = ".zig-cache/bench-netaddr";

const Inputs = struct {
    v4_text: [][]const u8,
    v6_text: [][]const u8,
    v6: []netaddr.Ip,
    mixed: []netaddr.Ip,
    prefixes: []netaddr.Prefix,
    probes: []netaddr.Ip,
    set_prefixes: []netaddr.Prefix,
    set: netaddr.IpSet,
};

fn randV6(r: std.Random) [16]u8 {
    var a: [16]u8 = undefined;
    r.bytes(&a);
    // Runs of zero groups, so `::` compression is exercised.
    switch (r.uintLessThan(u8, 4)) {
        0 => @memset(a[4..12], 0),
        1 => @memset(a[0..10], 0),
        2 => {
            a[0] = 0x20;
            a[1] = 0x01;
            a[2] = 0x0d;
            a[3] = 0xb8;
            @memset(a[8..14], 0);
        },
        else => {},
    }
    return a;
}

fn randIp(r: std.Random) netaddr.Ip {
    if (r.boolean()) {
        var a: [4]u8 = undefined;
        r.bytes(&a);
        return .{ .v4 = a };
    }
    return .{ .v6 = randV6(r) };
}

fn randPrefix(r: std.Random) netaddr.Prefix {
    const ip = randIp(r);
    const bits: u8 = switch (ip) {
        .v4 => 8 + r.uintLessThan(u8, 25),
        .v6 => 16 + r.uintLessThan(u8, 113),
    };
    return ip.prefix(bits).?;
}

fn writeLines(io: std.Io, dir: std.Io.Dir, gpa: std.mem.Allocator, name: []const u8, items: anytype) !void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    for (items) |it| {
        switch (@TypeOf(it)) {
            []const u8 => try out.writer.writeAll(it),
            else => try it.format(&out.writer),
        }
        try out.writer.writeByte('\n');
    }
    try dir.writeFile(io, .{ .sub_path = name, .data = out.written() });
}

fn genInputs(gpa: std.mem.Allocator) !Inputs {
    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_0a11);
    const r = prng.random();
    var in: Inputs = undefined;
    in.v4_text = try gpa.alloc([]const u8, n_inputs);
    for (in.v4_text) |*t| {
        var a: [4]u8 = undefined;
        r.bytes(&a);
        t.* = try std.fmt.allocPrint(gpa, "{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] });
    }
    in.v6 = try gpa.alloc(netaddr.Ip, n_inputs);
    in.v6_text = try gpa.alloc([]const u8, n_inputs);
    for (in.v6, in.v6_text) |*ip, *t| {
        ip.* = .{ .v6 = randV6(r) };
        var buf: [netaddr.max_ip_text_len]u8 = undefined;
        t.* = try gpa.dupe(u8, netaddr.formatIp(ip.*, &buf));
    }
    in.mixed = try gpa.alloc(netaddr.Ip, n_inputs);
    for (in.mixed) |*ip| ip.* = randIp(r);
    in.prefixes = try gpa.alloc(netaddr.Prefix, n_inputs);
    in.probes = try gpa.alloc(netaddr.Ip, n_inputs);
    for (in.prefixes, in.probes) |*p, *ip| {
        p.* = randPrefix(r);
        // Half the probes inside their prefix, half drawn at random.
        ip.* = if (r.boolean()) p.addr else randIp(r);
    }
    in.set_prefixes = try gpa.alloc(netaddr.Prefix, n_set);
    for (in.set_prefixes) |*p| p.* = randPrefix(r);
    var b: netaddr.IpSetBuilder = .empty;
    defer b.deinit(gpa);
    for (in.set_prefixes) |p| try b.addPrefix(gpa, p);
    in.set = try b.toSet(gpa);
    return in;
}

// ── workloads ───────────────────────────────────────────────────────────────

const gpa_fast = std.heap.smp_allocator;

fn parseV4(in: *const Inputs) usize {
    var k: usize = 0;
    for (in.v4_text) |t| k += @intFromBool(netaddr.parseIp(t) != null);
    return k;
}
fn parseV6(in: *const Inputs) usize {
    var k: usize = 0;
    for (in.v6_text) |t| k += @intFromBool(netaddr.parseIp(t) != null);
    return k;
}
fn formatV6(in: *const Inputs) usize {
    var k: usize = 0;
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    for (in.v6) |ip| k += netaddr.formatIp(ip, &buf).len;
    return k;
}
fn prefixContains(in: *const Inputs) usize {
    var k: usize = 0;
    for (in.prefixes, in.probes) |p, ip| k += @intFromBool(p.contains(ip));
    return k;
}
fn lessThan(_: void, a: netaddr.Ip, b: netaddr.Ip) bool {
    return a.compare(b) == .lt;
}
fn sortMixed(in: *const Inputs) usize {
    var scratch: [n_inputs]netaddr.Ip = undefined;
    @memcpy(&scratch, in.mixed);
    std.mem.sort(netaddr.Ip, &scratch, {}, lessThan);
    // Where the first v6 address landed: v4 sorts before v6.
    for (scratch, 0..) |ip, i| if (ip == .v6) return i;
    return scratch.len;
}
fn setBuild(in: *const Inputs) usize {
    var b: netaddr.IpSetBuilder = .empty;
    defer b.deinit(gpa_fast);
    for (in.set_prefixes) |p| b.addPrefix(gpa_fast, p) catch unreachable;
    var s = b.toSet(gpa_fast) catch unreachable;
    defer s.deinit(gpa_fast);
    return s.rangeCount();
}
fn setContains(in: *const Inputs) usize {
    var k: usize = 0;
    for (in.probes) |ip| k += @intFromBool(in.set.contains(ip));
    return k;
}

const Workload = struct { name: []const u8, f: *const fn (*const Inputs) usize };
const workloads = [_]Workload{
    .{ .name = "parse_v4", .f = parseV4 },
    .{ .name = "parse_v6", .f = parseV6 },
    .{ .name = "format_v6", .f = formatV6 },
    .{ .name = "prefix_contains", .f = prefixContains },
    .{ .name = "sort_mixed", .f = sortMixed },
    .{ .name = "set_build", .f = setBuild },
    .{ .name = "set_contains", .f = setContains },
};

fn timeIt(io: std.Io, in: *const Inputs, f: *const fn (*const Inputs) usize) struct { ns: f64, count: usize } {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(f(in));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = f(in);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);

    const in = try genInputs(arena);
    try writeLines(io, dir, arena, "v4.txt", in.v4_text);
    try writeLines(io, dir, arena, "v6.txt", in.v6_text);
    try writeLines(io, dir, arena, "mixed.txt", in.mixed);
    try writeLines(io, dir, arena, "prefixes.txt", in.prefixes);
    try writeLines(io, dir, arena, "probes.txt", in.probes);
    try writeLines(io, dir, arena, "set.txt", in.set_prefixes);

    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    std.debug.print("bench-netaddr: Go net/netip + netipx ...\n", .{});
    const go = std.process.run(arena, io, .{
        .argv = &.{ "go", "run", ".", abs },
        .environ_map = &env,
        .cwd = .{ .path = "modules/netaddr/tools/go_bench" },
    }) catch |e| {
        std.debug.print("bench-netaddr: could not run go ({t}) -- the benchmark needs it\n", .{e});
        return 1;
    };
    if (go.term != .exited or go.term.exited != 0) {
        std.debug.print("bench-netaddr: go_bench failed:\n{s}\n", .{go.stderr});
        return 1;
    }
    const GoRow = struct { ns: f64, count: usize };
    var go_rows: std.StringHashMapUnmanaged(GoRow) = .empty;
    var lines = std.mem.tokenizeScalar(u8, go.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadGoOutput);
        const count = try std.fmt.parseInt(usize, f.next() orelse return error.BadGoOutput, 10);
        try go_rows.put(arena, name, .{ .ns = ns, .count = count });
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<16} {s:>12} {s:>12} {s:>7}  count\n", .{ "workload", "ours ns/op", "go ns/op", "ours/go" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var mismatch = false;
    for (workloads) |wl| {
        const ours = timeIt(io, &in, wl.f);
        const theirs = go_rows.get(wl.name) orelse {
            std.debug.print("bench-netaddr: Go reported nothing for {s}\n", .{wl.name});
            return 1;
        };
        const ratio = ours.ns / theirs.ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        const same = ours.count == theirs.count;
        if (!same) mismatch = true;
        try w.print("{s:<16} {d:>12.1} {d:>12.1} {d:>7.2}  {d}{s}\n", .{ wl.name, ours.ns, theirs.ns, ratio, ours.count, if (same) "" else " ≠ Go" });
        try w.flush();
    }
    if (mismatch) {
        try w.writeAll("bench-netaddr: FAILED -- a result count differs from Go's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/go = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go net/netip + netipx · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
