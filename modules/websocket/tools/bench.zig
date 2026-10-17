// SPDX-License-Identifier: MIT

//! Comparative benchmark: `websocket` against github.com/coder/websocket
//! v1.8.15 (the reference), the program behind the `**Performance:**` line
//! of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-websocket` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! github.com/coder/websocket in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`). Run from the repository
//! root.
//!
//! Both sides are a server on an in-memory connection: reads come from a
//! buffer holding the client's frames, writes go to a discarding writer
//! (ours: `Connection.receive` over a copy of the wire -- the copy stands for
//! the read from the socket that coder's bufio reader does; coder: `Accept`
//! over a `net.Conn` whose reads cycle over the same bytes). No socket in
//! either number.
//!   read_text_small       16 masked text messages of ~64 B (JSON)
//!   read_text_fragmented  4 text messages of 4 KiB, 4 fragments each
//!   read_binary_64k       4 binary messages of 64 KiB
//!   read_deflate          16 compressed text messages of 2 KiB (compressed
//!                         by this module; coder decoding them is an interop
//!                         check as well)
//!   write_text_small      16 server text messages of ~64 B
//!   write_binary_64k      4 server binary messages of 64 KiB
//!   write_deflate         16 server text messages of 2 KiB, compressed
//!                         (level 1 = coder's flate.BestSpeed)
//! *_deflate negotiate permessage-deflate without context takeover on both
//! sides. Count: messages + payload bytes delivered (read), messages written
//! (write). Ours validates UTF-8 on every text message; coder does not (see
//! SPEC), so the read_text rows carry that check on our side only.
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best. Ratios are ours/coder by wall time; the verdict is the
//! WORST ratio. Arguments filter workloads. The program installs `fastmem`'s
//! memset (see the comptime block below).

const std = @import("std");
const bench = @import("testkit").bench;
const fastmem = @import("fastmem");
const websocket = @import("websocket");

// std 0.16's `flate.Compress.writeBlock` resets its 96 KiB token list with a
// memset once per message, and Zig 0.16's compiler_rt memset is byte-wise
// (no libc): write_deflate is 2.0x coder with it, 0.93x without
// (2026-10-11). Deployed libc-free executables here install fastmem (qap's
// do), so this one does too; the card records both numbers.
comptime {
    fastmem.exportSymbols();
}
const frame = websocket.frame;
const deflate = websocket.deflate;
const Connection = websocket.connection.Connection;

const bench_name = "bench-websocket";
const work_dir = ".zig-cache/bench-websocket";
const go_dir = "modules/websocket/tools/go_bench";
const ref_short = "coder";
const ref_card = "coder/websocket v1.8.15";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{};
const names = [_][]const u8{ "read_text_small", "read_text_fragmented", "read_binary_64k", "read_deflate", "write_text_small", "write_binary_64k", "write_deflate" };

const mask_key: [4]u8 = .{ 0x37, 0xfa, 0x21, 0x3d };

const Data = struct {
    /// read_*: the client frames; write_*: unused.
    wires: [names.len][]const u8,
    /// write_*: the messages to send.
    payloads: [names.len][]const []const u8,
    msgs: [names.len]usize,
    scratch: []u8,
    msg_buf: []u8,
    cbuf: []u8,
    window: *deflate.Window,
    compressor: *deflate.Compressor,
    comp_out: []u8,
};

fn isRead(w: usize) bool {
    return std.mem.startsWith(u8, names[w], "read_");
}

fn once(d: *const Data, w: usize) u64 {
    var sum: u64 = 0;
    if (isRead(w)) {
        const wire = d.scratch[0..d.wires[w].len];
        @memcpy(wire, d.wires[w]);
        var conn: Connection = .init(.server, d.msg_buf, 1 << 20);
        if (std.mem.endsWith(u8, names[w], "_deflate")) conn.enableDeflate(d.cbuf, d.window);
        var off: usize = 0;
        while (off < wire.len) {
            const r = conn.receive(wire[off..]) catch unreachable;
            switch (r.event) {
                .message => |m| sum += m.payload.len + 1,
                .frame_consumed => {},
                else => unreachable,
            }
            off += r.consumed;
        }
        return sum;
    }
    var buf: [4096]u8 = undefined;
    var disc: std.Io.Writer.Discarding = .init(&buf);
    const deflating = std.mem.endsWith(u8, names[w], "_deflate");
    const opcode: frame.Opcode = if (std.mem.indexOf(u8, names[w], "binary") != null) .binary else .text;
    for (d.payloads[w]) |p| {
        if (deflating) {
            if (d.compressor.compressMessage(p, d.comp_out, 1)) |z| {
                frame.writeFrame(&disc.writer, .{ .opcode = opcode, .payload = z, .compressed = true }) catch unreachable;
                sum += 1;
                continue;
            }
        }
        frame.writeFrame(&disc.writer, .{ .opcode = opcode, .payload = p }) catch unreachable;
        sum += 1;
    }
    disc.writer.flush() catch unreachable;
    return sum;
}

fn jsonMessage(arena: std.mem.Allocator, r: std.Random, len: usize) ![]u8 {
    var a: std.Io.Writer.Allocating = .init(arena);
    var i: usize = 0;
    try a.writer.writeAll("{\"events\":[");
    while (a.written().len + 2 < len) : (i += 1) {
        try a.writer.print("{{\"id\":{d},\"kind\":\"{s}\",\"v\":{d}}},", .{ i, ([_][]const u8{ "tick", "update", "price", "ack" })[r.uintLessThan(usize, 4)], r.uintLessThan(u32, 100000) });
    }
    const out = a.written()[0..len];
    out[len - 2] = ']';
    out[len - 1] = '}';
    return out;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var d: Data = undefined;
    var prng: std.Random.DefaultPrng = .init(6455);
    const r = prng.random();
    d.compressor = try arena.create(deflate.Compressor);
    d.window = try arena.create(deflate.Window);
    d.msg_buf = try arena.alloc(u8, 1 << 20);
    d.cbuf = try arena.alloc(u8, 1 << 20);
    d.comp_out = try arena.alloc(u8, 1 << 17);
    var max_wire: usize = 0;
    for (names, 0..) |name, wi| {
        var msgs: std.ArrayList([]const u8) = .empty;
        const n: usize, const len: usize = if (std.mem.indexOf(u8, name, "small") != null)
            .{ 16, 64 }
        else if (std.mem.indexOf(u8, name, "fragmented") != null)
            .{ 4, 4096 }
        else if (std.mem.indexOf(u8, name, "64k") != null)
            .{ 4, 64 * 1024 }
        else
            .{ 16, 2048 };
        for (0..n) |_| {
            const p = if (std.mem.indexOf(u8, name, "binary") != null) blk: {
                const b = try arena.alloc(u8, len);
                for (b) |*x| x.* = 1 + r.uintLessThan(u8, 255); // no 0x00: the write files are \x00-separated
                break :blk b;
            } else try jsonMessage(arena, r, len);
            try msgs.append(arena, p);
        }
        d.payloads[wi] = msgs.items;
        d.msgs[wi] = n;
        var all: std.Io.Writer.Allocating = .init(arena);
        if (isRead(wi)) {
            const opcode: frame.Opcode = if (std.mem.indexOf(u8, name, "binary") != null) .binary else .text;
            for (msgs.items) |p| {
                if (std.mem.endsWith(u8, name, "_deflate")) {
                    const z = d.compressor.compressMessage(p, d.comp_out, 1).?;
                    try frame.writeFrame(&all.writer, .{ .opcode = opcode, .payload = z, .mask_key = mask_key, .compressed = true });
                } else if (std.mem.indexOf(u8, name, "fragmented") != null) {
                    const q = p.len / 4;
                    for (0..4) |k| try frame.writeFrame(&all.writer, .{
                        .fin = k == 3,
                        .opcode = if (k == 0) opcode else .continuation,
                        .payload = p[k * q .. if (k == 3) p.len else (k + 1) * q],
                        .mask_key = mask_key,
                    });
                } else try frame.writeFrame(&all.writer, .{ .opcode = opcode, .payload = p, .mask_key = mask_key });
            }
            d.wires[wi] = all.written();
            max_wire = @max(max_wire, all.written().len);
            try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}.count", .{name}), .data = try std.fmt.allocPrint(arena, "{d}\n", .{n}) });
        } else {
            for (msgs.items, 0..) |p, i| {
                if (i != 0) try all.writer.writeByte(0);
                try all.writer.writeAll(p);
            }
            d.wires[wi] = "";
        }
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}.wire", .{name}), .data = all.written() });
    }
    d.scratch = try arena.alloc(u8, max_wire);
    return d;
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
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var d: Data = try setup(arena, io, dir);
    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs, .toolchain = "go1.26.0" });
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ &d, wi }, true));
        }
        const gross = ours.best_ns / go.best_ns;
        // `net_base` (a workload name): the cost of the HTTP stacks both sides
        // carry is that workload; the module's own ratio is what is left over.
        var net: f64 = std.math.nan(f64);
        if (net_base) |nb| {
            if (std.mem.eql(u8, nb, name)) {
                base_ours = ours.best_ns;
                base_ref = go.best_ns;
            } else if (base_ref != 0 and go.best_ns > base_ref) {
                net = (ours.best_ns - base_ours) / (go.best_ns - base_ref);
            }
        }
        const ratio = if (net_base != null and !std.math.isNan(net)) net else gross;
        const info = for (info_only) |n| {
            if (std.mem.eql(u8, n, name)) break true;
        } else false;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(false), go.spread(false)));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(false), 100 * go.spread(false), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ " ++ ref_short });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}
