// SPDX-License-Identifier: MIT

//! Comparative benchmark: `mcp` (the MCP server core) against the official Go
//! SDK, github.com/modelcontextprotocol/go-sdk v1.8.0 (the reference), the
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-mcp` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! github.com/modelcontextprotocol/go-sdk in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`). Run from the repository
//! root.
//!
//! One op = one whole session, protocol 2025-11-25, newline-delimited
//! JSON-RPC: `initialize`, `notifications/initialized`, then 64 requests of
//! one kind. The request bytes are written here and read by both sides.
//!   tools_call_echo   tools/call of `echo` ({"text"} in, {"echo":text} out;
//!                     ours declares both schemas, the Go SDK infers them from
//!                     its typed In/Out structs; both validate input and output)
//!   tools_list_20     tools/list over 20 registered tools, small schemas
//!   resources_read    resources/read of a static 1 KiB text resource
//!   prompts_get       prompts/get of a prompt with one required argument
//!   initialize_only   the handshake + 64 pings
//! Ours: `Server.serve` over a fixed reader and a fixed writer (the server and
//! its registry are built once; per-message arenas come from the allocator,
//! as in production). The reference: `Server.Run` over `mcp.IOTransport` (the
//! SDK's stdio framing) on in-memory bytes, the server built once and a
//! session run per op.
//!
//! ASYMMETRY (inherent, left in the number): the SDK's stdio path is a
//! jsonrpc2 connection with a reader goroutine and one goroutine per request,
//! and it abandons requests still in flight when its reader ends. The Go side
//! therefore withholds the reader's EOF until every request has been answered
//! (what a client waiting for its answers does), so a session pays that
//! goroutine hand-off per op. Ours is the single-threaded `serve` loop, which
//! is how this module is run. Both stacks are in the number, no baseline is
//! subtracted.
//!
//! The result count is the number of response lines plus the number of
//! `"isError":true` occurrences (field order differs, so bytes are not
//! compared); the run fails if the sides disagree. Each side times the same
//! way (double the batch until it takes over 100 ms, best of five); the sides
//! alternate for BENCH_ROUNDS (default 3) rounds, each keeping its best.
//! Ratios are ours/reference by wall time (the Go side counts no cycles); the
//! verdict is the WORST ratio. Arguments filter workloads.
//!
//! The fastest in the field is timed beside it: `tools/rs_field`, the official
//! Rust SDK rmcp 3.7.0 (pinned with its Cargo.lock; `cargo build --release
//! --offline`, `BENCH_FAST=0` skips it), over the same session bytes and with
//! the same count. rmcp has no schema validation on this path, so its echo
//! row validates nothing (see its header). The card's `fastest` figure is
//! ours / min(Go, rmcp) per workload, worst over the workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const mcp = @import("mcp");

const bench_name = "bench-mcp";
const work_dir = ".zig-cache/bench-mcp";
const go_dir = "modules/mcp/tools/go_bench";
const ref_short = "ref";
const ref_card = "modelcontextprotocol/go-sdk v1.8.0";
const fast_rs_manifest = "modules/mcp/tools/rs_field/Cargo.toml";
const fast_rs_exe = "modules/mcp/tools/rs_field/target/release/mcp_rs_field";

const names = [_][]const u8{ "tools_call_echo", "tools_list_20", "resources_read", "prompts_get", "initialize_only" };
const n_req = 64;
const resource_uri = "file:///doc.txt";

const Data = struct {
    servers: [names.len]*mcp.Server,
    wires: [names.len][]const u8,
};

var out_buf: [4 << 20]u8 = undefined;
var doc_text: [1024]u8 = undefined;

fn hEcho(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    const text = call.requireStr("text") orelse return true;
    call.print("{{\"echo\":\"{s}\"}}", .{text});
    return false;
}

fn hNoop(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.write("ok");
    return false;
}

fn hDoc(_: ?*anyopaque, req: *mcp.ResourceRequest) bool {
    req.text(resource_uri, "text/plain", &doc_text);
    return true;
}

fn hGreet(_: ?*anyopaque, req: *mcp.PromptRequest) bool {
    const who = req.strArg("name") orelse return false;
    req.printMessage(.user, "Hello, {s}!", .{who});
    return true;
}

const greet_args = [_]mcp.PromptArgument{.{ .name = "name", .required = true }};

fn once(d: *const Data, w: usize) u64 {
    var in: std.Io.Reader = .fixed(d.wires[w]);
    var out: std.Io.Writer = .fixed(&out_buf);
    d.servers[w].serve(&in, &out) catch @panic("mcp serve failed");
    const resp = out.buffered();
    // Same line count is no proof of the same work: a JSON-RPC error answers
    // one line too. Both sides refuse a session that produced one.
    if (std.mem.find(u8, resp, "\"error\":{") != null) @panic("mcp answered a JSON-RPC error");
    return std.mem.count(u8, resp, "\n") + std.mem.count(u8, resp, "\"isError\":true");
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    for (&doc_text, 0..) |*c, i| c.* = "0123456789abcdef"[i % 16];
    var d: Data = undefined;
    for (names, 0..) |name, wi| {
        const s = try arena.create(mcp.Server);
        s.* = mcp.Server.init(std.heap.smp_allocator, .{ .name = "bench", .version = "1.0.0" });
        d.servers[wi] = s;
        switch (wi) {
            0 => try s.addTool(.{
                .name = "echo",
                .description = "Echo the text back",
                .input_schema = "{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\"}},\"required\":[\"text\"]}",
                .output_schema = "{\"type\":\"object\",\"properties\":{\"echo\":{\"type\":\"string\"}},\"required\":[\"echo\"]}",
                .handler = hEcho,
            }),
            1 => inline for (0..20) |i| try s.addTool(.{
                .name = std.fmt.comptimePrint("tool_{d:0>2}", .{i}),
                .description = std.fmt.comptimePrint("Small tool number {d}", .{i}),
                .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"},\"b\":{\"type\":\"integer\"}},\"required\":[\"a\"]}",
                .handler = hNoop,
            }),
            2 => try s.addResource(.{ .uri = resource_uri, .name = "doc", .mime_type = "text/plain", .handler = hDoc }),
            3 => try s.addPrompt(.{ .name = "greet", .description = "Greet someone", .arguments = &greet_args, .handler = hGreet }),
            else => {},
        }

        var all: std.Io.Writer.Allocating = .init(arena);
        const aw = &all.writer;
        try aw.writeAll("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"bench\",\"version\":\"1\"}}}\n");
        try aw.writeAll("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
        for (0..n_req) |i| {
            const id = i + 2;
            switch (wi) {
                0 => try aw.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"text\":\"hello {d}\"}}}}}}\n", .{ id, i }),
                1 => try aw.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"tools/list\",\"params\":{{}}}}\n", .{id}),
                2 => try aw.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"resources/read\",\"params\":{{\"uri\":\"{s}\"}}}}\n", .{ id, resource_uri }),
                3 => try aw.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"prompts/get\",\"params\":{{\"name\":\"greet\",\"arguments\":{{\"name\":\"user {d}\"}}}}}}\n", .{ id, i }),
                else => try aw.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"ping\"}}\n", .{id}),
            }
        }
        d.wires[wi] = all.written();
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.wire", .{name}), .data = all.written() });
    }
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

    const d: Data = try setup(arena, io, dir);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const use_fast = if (init.environ_map.get("BENCH_FAST")) |v| !std.mem.eql(u8, v, "0") else true;
    if (use_fast) rustBuild(arena, io) catch return 1;
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<18} {s:>12} {s:>12} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "/ref", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var worst_fast: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var rs_banner: []const u8 = "";
    for (names, 0..) |name, wi| {
        if (!bench.selected(name, filters)) continue;
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        var rs: bench.Side = .{};
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            if (use_fast) rs.add(try bench.foreign(arena, io, bench_name, fast_rs_exe, abs, name, &rs_banner));
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ &d, wi }, true));
        }
        const ratio = ours.best_ns / go.best_ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        max_spread = @max(max_spread, @max(ours.spread(false), go.spread(false)));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<18} {d:>12.0} {d:>12.0} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, ratio, 100 * ours.spread(false), 100 * go.spread(false), ours.count, if (same) "" else " ≠ " ++ ref_short });
        if (use_fast) {
            const rs_same = rs.count == go.count;
            mismatch = mismatch or !rs_same;
            max_spread = @max(max_spread, rs.spread(false));
            worst_fast = @max(worst_fast, ours.best_ns / @min(go.best_ns, rs.best_ns));
            try w.print("{s:<18} {s:>12} {d:>12.0} {d:>8.3} {s:>7} {d:>6.1}%  rmcp{s}\n", .{ "", "", rs.best_ns, ours.best_ns / rs.best_ns, "", 100 * rs.spread(false), if (rs_same) "" else " ≠ " ++ ref_short });
        }
        try w.flush();
    }
    if (rs_banner.len > 0) try w.print("field: {s}\n", .{std.mem.trim(u8, rs_banner, " \n")});
    try w.print("rounds: {d}; ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (use_fast) try w.print("worst ours/fastest = {d:.2}\n", .{worst_fast});
    if (filters.len == 0) {
        if (use_fast)
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× rmcp 3.7.0 (Rust) (measured <today>)\n", .{ best, worst, ref_card, worst_fast })
        else
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    }
    try w.flush();
    return 0;
}

/// `cargo build --release --offline` of tools/rs_field.
fn rustBuild(arena: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--quiet", "--manifest-path", fast_rs_manifest },
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- BENCH_FAST=0 skips this side\n", .{ bench_name, e });
        return error.CargoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.CargoBuildFailed;
    }
}
