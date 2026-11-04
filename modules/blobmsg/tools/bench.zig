// SPDX-License-Identifier: MIT

//! Comparative benchmark: `blobmsg`'s codec against OpenWrt libubox's blobmsg + json-c
//! (the reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md section 9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-blobmsg` runs it (always ReleaseFast);
//! `zig build check-interop` compiles it. Run from the repository root, through `hw run`.
//! Needs `zig` on PATH and the reviewed libubox and json-c trees built once (json-c's
//! generated headers) in `BLOBMSG_FOREIGN` (default
//! `~/workspace/zig-libs/.zig-cache/foreign-build`: `libubox/`, `json-c/`,
//! `json-c-build/`); the driver compiles the C side from those sources with
//! `zig cc -O3 -march=native` (json-c included, so the same flags and compiler apply
//! to the whole C side) into `.zig-cache/bench-blobmsg/`.
//!
//! Three documents, written by this driver and read by the C side: `small` (an
//! `ubus call` argument object, ~90 bytes), `status` (an interface-status-shaped reply,
//! 1.1 KB, nested tables and arrays), `large` (an array of 300 lease-like objects,
//! 50 KB). Only ASCII, no `/`, no non-integer numbers: both sides print them the same
//! (libubox prints doubles with 17 digits and json-c escapes `/`, neither is the point
//! here and a different text length would fail the count check).
//!
//! Rows (the same work on both sides; the allocator is `smp_allocator` for ours, malloc
//! for C; both allocate per op, which is what a caller of either API pays):
//!   json2blob.<doc>  JSON text to blobmsg bytes, parse included. Ours:
//!                    `std.json.parseFromSlice(Value)` + `codec.encodeArgs`
//!                    (what `Client.invoke` does with its argument string). C: json-c
//!                    parse + `blobmsg_add_json_from_string` into a reused `blob_buf`
//!                    (`blob_buf_init` each op). Count = bytes of the body.
//!   blob2json.<doc>  blobmsg bytes to JSON text. Ours `codec.decodeToJsonAlloc`; C
//!                    `blobmsg_format_json` (malloc'd, freed). Count = text length.
//!   walk.<doc>       a full validating walk of every attribute, nested: ours
//!                    `FieldIterator` (recursive), C `blobmsg_check_attr` +
//!                    the typed getters; both add up field count, name lengths, string
//!                    lengths and integer values. Count = that sum.
//!
//! `fastest ?`: no second blobmsg JSON codec exists to compare (jbit/ubus-rs has a blob
//! TLV and lookup only, goubus and golangwrt/ubus wrap libubus or rpcd), so the
//! reference is the only measured implementation. Reference and fastest are not the
//! same implementation here only because there is just one.
//!
//! Arguments filter workloads (a substring of `op.doc`). Not a card line when filtered.

const std = @import("std");
const bench = @import("testkit").bench;
const blobmsg = @import("blobmsg");
const codec = blobmsg.codec;

const bench_name = "bench-blobmsg";
const work_dir = ".zig-cache/bench-blobmsg";
const ref_short = "libubox";
const ref_card = "libubox a396f38a + json-c d9b375ff (zig cc -O3 -march=native)";
const docs = [_][]const u8{ "small", "status", "large" };
const kinds = [_][]const u8{ "json2blob", "blob2json", "walk" };

const Op = struct { kind: u8, doc: u8 };

const Ctx = struct {
    op: Op = .{ .kind = 0, .doc = 0 },
    text: [docs.len][]const u8 = undefined,
    body: [docs.len][]const u8 = undefined,
};

const gpa = std.heap.smp_allocator;

// ── the timed ops ────────────────────────────────────────────────────────────

fn once(c: *Ctx) u64 {
    const d = c.op.doc;
    switch (c.op.kind) {
        0 => {
            var parsed = std.json.parseFromSlice(std.json.Value, gpa, c.text[d], .{}) catch @panic("bench-blobmsg: parse");
            defer parsed.deinit();
            const bytes = codec.encodeArgs(gpa, parsed.value) catch @panic("bench-blobmsg: encode");
            defer gpa.free(bytes);
            std.mem.doNotOptimizeAway(bytes.ptr);
            return bytes.len;
        },
        1 => {
            const s = codec.decodeToJsonAlloc(gpa, c.body[d]) catch @panic("bench-blobmsg: decode");
            defer gpa.free(s);
            std.mem.doNotOptimizeAway(s.ptr);
            return s.len;
        },
        else => {
            var n: u64 = 0;
            var sum: u64 = 0;
            walk(c.body[d], &n, &sum);
            return n +% sum;
        },
    }
}

fn walk(children: []const u8, n: *u64, sum: *u64) void {
    var it = codec.FieldIterator.init(children);
    while (it.next() catch @panic("bench-blobmsg: walk")) |f| {
        n.* += 1;
        sum.* +%= f.name.len;
        switch (f.value) {
            .string => |s| sum.* +%= s.len,
            .boolean => |b| sum.* +%= @intFromBool(b),
            .int16 => |v| sum.* +%= @as(u16, @bitCast(v)),
            .int32 => |v| sum.* +%= @as(u32, @bitCast(v)),
            .int64 => |v| sum.* +%= @as(u64, @bitCast(v)),
            .table, .array => |ch| walk(ch, n, sum),
            .double, .unknown => {},
        }
    }
}

// ── the documents ────────────────────────────────────────────────────────────

fn genSmall(a: std.mem.Allocator) ![]const u8 {
    return a.dupe(u8, "{\"name\":\"wan\",\"proto\":\"dhcp\",\"up\":true,\"metric\":10,\"mtu\":1500,\"ifname\":[\"eth1\",\"eth2\"]}");
}

fn genStatus(a: std.mem.Allocator) ![]const u8 {
    var o: std.ArrayList(u8) = .empty;
    try o.appendSlice(a, "{\"up\":true,\"pending\":false,\"available\":true,\"autostart\":true,\"dynamic\":false,\"uptime\":1234567,\"l3_device\":\"eth1\",\"proto\":\"dhcp\",\"device\":\"eth1\",\"metric\":0,\"delegation\":true,\"ipv4-address\":[");
    for (0..3) |i| try o.print(a, "{s}{{\"address\":\"192.168.{d}.{d}\",\"mask\":24}}", .{ if (i > 0) "," else "", i, 10 + i });
    try o.appendSlice(a, "],\"ipv6-address\":[],\"ipv6-prefix\":[],\"route\":[");
    for (0..6) |i| try o.print(a, "{s}{{\"target\":\"10.{d}.0.0\",\"mask\":16,\"nexthop\":\"192.168.1.1\",\"source\":\"192.168.1.2\"}}", .{ if (i > 0) "," else "", i });
    try o.appendSlice(a, "],\"dns-server\":[\"192.168.1.1\",\"8.8.8.8\"],\"dns-search\":[\"lan\"],\"neighbors\":[],\"inactive\":{\"ipv4-address\":[],\"ipv6-address\":[],\"route\":[],\"dns-server\":[],\"dns-search\":[],\"neighbors\":[]},\"data\":{\"leasetime\":43200,\"lease\":{\"id\":9007199254740993,\"flags\":[\"a\",\"b\",\"c\"],\"owner\":\"dhcp\"}}}");
    return o.items;
}

fn genLarge(a: std.mem.Allocator) ![]const u8 {
    var o: std.ArrayList(u8) = .empty;
    try o.appendSlice(a, "{\"leases\":[");
    for (0..300) |i| try o.print(a, "{s}{{\"mac\":\"00:11:22:33:{x:0>2}:{x:0>2}\",\"ip\":\"10.0.{d}.{d}\",\"hostname\":\"host-{d}\",\"expires\":{d},\"active\":{s},\"static\":false,\"tags\":[\"lan\",\"wifi\"],\"rx\":{d},\"tx\":{d}}}", .{
        if (i > 0) "," else "", i / 256,       i % 256,      i / 250,
        i % 250,                i,             3600 + i * 7, if (i % 3 == 0) "true" else "false",
        i * 123456789,          i * 987654321,
    });
    try o.appendSlice(a, "],\"count\":300}");
    return o.items;
}

// ── the C side ───────────────────────────────────────────────────────────────

const json_c_sources = [_][]const u8{ "arraylist", "debug", "json_c_version", "json_object", "json_object_iterator", "json_pointer", "json_tokener", "json_util", "json_visit", "linkhash", "printbuf", "random_seed", "strerror_override" };
const libubox_sources = [_][]const u8{ "blob", "blobmsg", "blobmsg_json" };

fn buildC(arena: std.mem.Allocator, io: std.Io, fb: []const u8, abs: []const u8) ![]const u8 {
    const exe = try arena.print("{s}/bench_libubox", .{abs});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "zig", "cc", "-O3", "-march=native", "-std=gnu99", "-D_GNU_SOURCE", "-w" });
    try argv.append(arena, try arena.print("-I{s}", .{fb}));
    try argv.append(arena, try arena.print("-I{s}/json-c", .{fb}));
    try argv.append(arena, try arena.print("-I{s}/json-c-build", .{fb}));
    try argv.appendSlice(arena, &.{ "-iquote", try arena.print("{s}/libubox", .{fb}) });
    try argv.append(arena, "modules/blobmsg/tools/bench_libubox.c");
    for (libubox_sources) |s| try argv.append(arena, try arena.print("{s}/libubox/{s}.c", .{ fb, s }));
    for (json_c_sources) |s| try argv.append(arena, try arena.print("{s}/json-c/{s}.c", .{ fb, s }));
    try argv.appendSlice(arena, &.{ "-lm", "-o", exe });
    std.debug.print("{s}: building the libubox + json-c side from {s} ...\n", .{ bench_name, fb });
    const res = try std.process.run(arena, io, .{ .argv = argv.items });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: zig cc failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.ForeignBuildFailed;
    }
    return exe;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;
    const fb = init.environ_map.get("BLOBMSG_FOREIGN") orelse blk: {
        const home = init.environ_map.get("HOME") orelse return error.NoHome;
        break :blk try arena.print("{s}/workspace/zig-libs/.zig-cache/foreign-build", .{home});
    };

    var ctx: Ctx = .{};
    const gens = [_]*const fn (std.mem.Allocator) anyerror![]const u8{ genSmall, genStatus, genLarge };
    for (docs, gens, 0..) |name, g, i| {
        ctx.text[i] = try g(arena);
        var parsed = try std.json.parseFromSlice(std.json.Value, arena, ctx.text[i], .{});
        defer parsed.deinit();
        ctx.body[i] = try codec.encodeArgs(arena, parsed.value);
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.json", .{name}), .data = ctx.text[i] });
        std.debug.print("{s}: {s}: {d} bytes of JSON, {d} of blobmsg\n", .{ bench_name, name, ctx.text[i].len, ctx.body[i].len });
    }

    const exe = try buildC(arena, io, fb, abs);
    const W = bench.Work(Op);
    var ws: [kinds.len * docs.len]W = undefined;
    var k: usize = 0;
    for (kinds, 0..) |kind, ki| for (docs, 0..) |doc, di| {
        const nm = try arena.print("{s}.{s}", .{ kind, doc });
        ws[k] = .{ .name = nm, .op = .{ .kind = @intCast(ki), .doc = @intCast(di) }, .ref = nm };
        k += 1;
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{exe},
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, &ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\nreference: {s}", .{ ref_short, s.worst_ref, s.best_ref, s.banner });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}-{d:.2}x {s} · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref, ref_card });
    try w.flush();
    return 0;
}
