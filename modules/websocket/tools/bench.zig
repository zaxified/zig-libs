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
//! the read from the socket that coder's bufio reader does, and is how qap
//! reads, an accumulator in front of `Connection`; coder: `Accept` over a
//! `net.Conn` whose reads cycle over the same bytes). No socket in either
//! number. Measured 2026-10-26 and NOT the card's number: `conn.Conn` over a
//! `std.Io.Reader` with a 128 KiB buffer cycling over the wire takes
//! read_binary_64k to 1.44x fastwebsockets (this harness: 1.19-1.25x) --
//! the reader's greedy fills leave every other 64 KiB frame half in the
//! buffer, copied a second time; fastwebsockets reserves payload + 14 bytes
//! and reads exactly one frame (SPEC "Performance").
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
//!
//! The fastest in the field (since 2026-10-26), every serious candidate
//! measured on the same wire bytes, same count, in the same rounds:
//!   gorilla/websocket v1.5.3        (`tools/go_bench/gorilla`; the most used
//!                                    Go library; permessage-deflate yes,
//!                                    UTF-8 validation no)
//!   denoland/fastwebsockets 0.10.0  (`tools/rust_fast_bench`; the usual
//!                                    "fastest" claim; async, driven by a
//!                                    no-op-waker poll; no permessage-deflate,
//!                                    UTF-8 yes)
//!   snapview/tungstenite 0.30.0     (same crate; sync, the most used Rust
//!                                    one; no permessage-deflate, UTF-8 yes)
//! A side that cannot do a workload (no permessage-deflate) prints n/a for it
//! and is not in that row's `fastest`. `fastest` is the best of coder, gorilla
//! and the Rust sides; `/fast` is ours / fastest. `BENCH_FAST=0` skips the
//! three added sides. NOT measured: uWebSockets (C++; it would need a pinned
//! checkout of uWebSockets + uSockets + a C++ driver feeding its
//! WebSocketProtocol parser over an in-memory buffer -- no socket loop).

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
const gorilla_dir = "modules/websocket/tools/go_bench/gorilla";
const rs_manifest = "modules/websocket/tools/rust_fast_bench/Cargo.toml";
const rs_exe = "modules/websocket/tools/rust_fast_bench/target/release/ws_fast_bench";
const ref_short = "coder";
const ref_card = "coder/websocket v1.8.15";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{};
const names = [_][]const u8{ "read_text_small", "read_text_fragmented", "read_binary_64k", "read_deflate", "write_text_small", "write_binary_64k", "write_deflate" };

/// The sides added for "fastest in the field" (besides the reference).
const Alt = struct {
    label: []const u8,
    /// First extra argument of the Rust program; null for the Go program.
    rust_lib: ?[]const u8,
    /// Can it do the permessage-deflate workloads?
    deflate: bool,
};
const alts = [_]Alt{
    .{ .label = "gorilla 1.5.3", .rust_lib = null, .deflate = true },
    .{ .label = "fastwebsockets 0.10.0", .rust_lib = "fastwebsockets", .deflate = false },
    .{ .label = "tungstenite 0.30.0", .rust_lib = "tungstenite", .deflate = false },
};

const mask_key: [4]u8 = .{ 0x37, 0xfa, 0x21, 0x3d };

const Data = struct {
    /// read_*: the client frames; write_*: unused.
    wires: [names.len][]const u8,
    /// write_*: the messages to send.
    payloads: [names.len][]const []const u8,
    msgs: [names.len]usize,
    msg_buf: []u8,
    cbuf: []u8,
    window: *deflate.Window,
    compressor: *deflate.Compressor,
    comp_out: []u8,
    scratch: []u8,
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
    const opcode: frame.Opcode = if (std.mem.find(u8, names[w], "binary") != null) .binary else .text;
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
        const n: usize, const len: usize = if (std.mem.find(u8, name, "small") != null)
            .{ 16, 64 }
        else if (std.mem.find(u8, name, "fragmented") != null)
            .{ 4, 4096 }
        else if (std.mem.find(u8, name, "64k") != null)
            .{ 4, 64 * 1024 }
        else
            .{ 16, 2048 };
        for (0..n) |_| {
            const p = if (std.mem.find(u8, name, "binary") != null) blk: {
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
            const opcode: frame.Opcode = if (std.mem.find(u8, name, "binary") != null) .binary else .text;
            for (msgs.items) |p| {
                if (std.mem.endsWith(u8, name, "_deflate")) {
                    const z = d.compressor.compressMessage(p, d.comp_out, 1).?;
                    try frame.writeFrame(&all.writer, .{ .opcode = opcode, .payload = z, .mask_key = mask_key, .compressed = true });
                } else if (std.mem.find(u8, name, "fragmented") != null) {
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
            try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.count", .{name}), .data = try arena.print("{d}\n", .{n}) });
        } else {
            for (msgs.items, 0..) |p, i| {
                if (i != 0) try all.writer.writeByte(0);
                try all.writer.writeAll(p);
            }
            d.wires[wi] = "";
        }
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.wire", .{name}), .data = all.written() });
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
    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const use_fast = if (init.environ_map.get("BENCH_FAST")) |v| !std.mem.eql(u8, v, "0") else true;
    const gorilla_exe = if (use_fast) try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = gorilla_dir, .abs = abs, .out = "go_bench_gorilla" }) else "";
    if (use_fast) try rustBuild(arena, io);
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var worst_fast: f64 = 0;
    var worst_fast_name: []const u8 = "";
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.find(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        var alt_sides: [alts.len]bench.Side = @splat(.{});
        const deflating = std.mem.endsWith(u8, name, "_deflate");
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            if (use_fast) for (alts, 0..) |alt, ai| {
                if (deflating and !alt.deflate) continue;
                const argv: []const []const u8 = if (alt.rust_lib) |lib|
                    &.{ rs_exe, abs, name, lib }
                else
                    &.{ gorilla_exe, abs, name };
                alt_sides[ai].add(try bench.foreignArgv(arena, io, bench_name, argv, name, null));
            };
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
        if (use_fast) {
            var fastest_ns = go.best_ns;
            var fastest_name: []const u8 = ref_short;
            for (alts, alt_sides) |alt, side| {
                if (deflating and !alt.deflate) {
                    try w.print("  {s:<20} {s:>11} {s:>8}\n", .{ alt.label, "n/a", "n/a" });
                    continue;
                }
                const same_alt = side.count == ours.count;
                mismatch = mismatch or !same_alt;
                max_spread = @max(max_spread, side.spread(false));
                if (side.best_ns < fastest_ns) {
                    fastest_ns = side.best_ns;
                    fastest_name = alt.label;
                }
                try w.print("  {s:<20} {d:>11.0} {d:>8.3} {d:>6.1}%{s}\n", .{ alt.label, side.best_ns, ours.best_ns / side.best_ns, 100 * side.spread(false), if (same_alt) "" else " (count differs)" });
            }
            const fast = ours.best_ns / fastest_ns;
            if (!info and fast > worst_fast) {
                worst_fast = fast;
                worst_fast_name = fastest_name;
            }
            try w.print("  {s:<20} {d:>11.0} {d:>8.3}  <- fastest in this row: ours/fastest\n", .{ fastest_name, fastest_ns, fast });
        }
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (use_fast) try w.print("worst ours/fastest = {d:.2} (fastest of that row: {s})\n", .{ worst_fast, worst_fast_name });
    if (filters.len == 0) {
        if (use_fast)
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× {s} (field: coder, gorilla, fastwebsockets, tungstenite; measured <today>)\n", .{ best, worst, ref_card, worst_fast, worst_fast_name })
        else
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    }
    try w.flush();
    return 0;
}

/// `cargo build --release --offline` of tools/rust_fast_bench.
fn rustBuild(arena: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("{s}: building the Rust sides ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--quiet", "--manifest-path", rs_manifest },
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- BENCH_FAST=0 skips the added sides\n", .{ bench_name, e });
        return error.CargoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.CargoBuildFailed;
    }
}
