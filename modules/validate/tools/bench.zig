// SPDX-License-Identifier: MIT

//! Comparative benchmark: `validate` against go-playground/validator v10.30.5
//! (the reference), the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-validate` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! github.com/go-playground/validator/v10 v10.30.5 (+ its dependencies) in the
//! module cache (pinned by `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`).
//! Run from the repository root.
//!
//! The unit of work is what a JSON endpoint does: BODY BYTES IN, VALIDATED
//! TYPED STRUCT OUT. Ours is `parseIntoLeaky(T, arena, body, .{})` with the
//! rules `T`'s fields and `validate_rules` give (arena reset per body); Go's is
//! `json.Unmarshal` into a struct followed by `validate.Struct` with the
//! equivalent tags. The Go validator is created once outside the timed loop
//! and warmed once -- it caches struct metadata, which is how it is used. One
//! op = 16 bodies of one shape:
//!   small    4-field signup (name, email, age, password), every body valid
//!   nested   an order: owner object + 10 line items (Go: `dive`), valid
//!   invalid  the signup body with 3 failing fields (name, email, age); BOTH
//!            sides report all 3
//!   formats  email + uuid4 + http_url, valid
//! Each shape has a `decode_<shape>` twin (Go: Unmarshal only; ours:
//! `std.json.parseFromSliceLeaky`): info only, EXCLUDED from the verdict, and
//! the verdict is the "net" ratio: (validating workload - its decode twin) per
//! side, the cost of validation itself. The gross ratio (decode included) is
//! printed beside it. Result count = per body 1 if it decoded and validated,
//! else the number of errors (decode_*: 1 per body that decoded).
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best. Ratios are ours/Go by wall time; the verdict is the WORST
//! net ratio over the four shapes. Arguments filter workloads (a filter that
//! leaves out a decode twin leaves its shape on the gross ratio).
//!
//! "Fastest in the field": `tools/rust_fast_bench` times jprochazk/garde 0.23.0
//! and Keats/validator 0.21.0 the same way (serde_json `from_slice` into a
//! `#[derive(Deserialize)]` struct + the crate's `validate()`, same bodies, same
//! count definition, each with its own decode twin so the verdict stays NET of
//! decoding). Rule equivalence is not exact (email, http_url = the crate's `url`
//! rule + an http(s) prefix check, uuid4 hand-written in both: the Rust source
//! header says where). `BENCH_FAST=0` skips it (needs cargo and the pinned
//! crates in ~/.cargo/registry). The card's fastest figure is ours / the
//! cheapest net cost of {go-playground, garde, validator} per row, worst over
//! the four shapes.

const std = @import("std");
const bench = @import("testkit").bench;
const validate = @import("validate");

const bench_name = "bench-validate";
const work_dir = ".zig-cache/bench-validate";
const go_dir = "modules/validate/tools/go_bench";
const ref_short = "go";
const ref_card = "go-playground/validator v10.30.5";

const fast_rs_manifest = "modules/validate/tools/rust_fast_bench/Cargo.toml";
const fast_rs_exe = "modules/validate/tools/rust_fast_bench/target/release/validate_fast_bench";
const fast_names = [_][]const u8{ "garde", "validator" };
const fast_cards = [_][]const u8{ "jprochazk/garde 0.23.0", "Keats/validator 0.21.0" };

const names = [_][]const u8{ "decode_small", "valid_small", "decode_nested", "valid_nested", "decode_invalid", "invalid", "decode_formats", "formats" };
const shapes = [_][]const u8{ "small", "nested", "invalid", "formats" };
const n_req = 16;

const Signup = struct {
    name: []const u8,
    email: []const u8,
    age: i32,
    password: []const u8,

    pub const validate_rules: []const validate.Rule = &.{
        .{ .field = "name", .kind = .string, .min_len = 2, .max_len = 64 },
        .{ .field = "email", .kind = .string, .format = .email },
        .{ .field = "age", .kind = .int, .min = 0, .max = 150 },
        .{ .field = "password", .kind = .string, .min_len = 8, .max_len = 72 },
    };
};

const Owner = struct { name: []const u8, email: []const u8 };
const Item = struct { sku: []const u8, qty: u16, price: f64 };
const Order = struct {
    id: []const u8,
    owner: Owner,
    items: []const Item,

    pub const validate_rules: []const validate.Rule = &.{
        .{ .field = "id", .kind = .string, .min_len = 1 },
        .{ .field = "owner", .kind = .object, .fields = &.{
            .{ .field = "name", .kind = .string, .min_len = 2, .max_len = 64 },
            .{ .field = "email", .kind = .string, .format = .email },
        } },
        .{ .field = "items", .kind = .array, .min_len = 1, .max_len = 100, .items = &.{ .field = "", .kind = .object, .fields = &.{
            .{ .field = "sku", .kind = .string, .min_len = 3, .max_len = 20 },
            .{ .field = "qty", .kind = .int, .min = 1, .max = 1000 },
            .{ .field = "price", .kind = .float, .min = 0 },
        } } },
    };
};

const Links = struct {
    email: []const u8,
    id: []const u8,
    url: []const u8,

    pub const validate_rules: []const validate.Rule = &.{
        .{ .field = "email", .kind = .string, .format = .email },
        .{ .field = "id", .kind = .string, .format = .uuid4 },
        .{ .field = "url", .kind = .string, .format = .http_url },
    };
};

const Data = struct {
    arena: std.heap.ArenaAllocator,
    bodies: [shapes.len][n_req][]const u8,
};

var sink: usize = 0;

/// One body, one side's way: decode only, or decode + validate. Returns the
/// result count (see the file header).
fn one(comptime T: type, a: std.mem.Allocator, body: []const u8, decode_only: bool) u64 {
    if (decode_only) {
        const v = std.json.parseFromSliceLeaky(T, a, body, .{ .ignore_unknown_fields = true }) catch return 0;
        sink +%= @field(v, @typeInfo(T).@"struct".field_names[0]).len;
        return 1;
    }
    const r = validate.parseIntoLeaky(T, a, body, .{}) catch return 0;
    switch (r) {
        .ok => |v| {
            sink +%= @field(v, @typeInfo(T).@"struct".field_names[0]).len;
            return 1;
        },
        .invalid => |rep| return rep.errors.len,
    }
}

fn once(d: *Data, w: usize) u64 {
    const shape = w / 2;
    const decode_only = w % 2 == 0;
    var sum: u64 = 0;
    for (d.bodies[shape]) |body| {
        _ = d.arena.reset(.retain_capacity);
        const a = d.arena.allocator();
        sum += switch (shape) {
            0, 2 => one(Signup, a, body, decode_only),
            1 => one(Order, a, body, decode_only),
            else => one(Links, a, body, decode_only),
        };
    }
    return sum;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var d: Data = undefined;
    d.arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    for (shapes, 0..) |shape, si| {
        var all: std.Io.Writer.Allocating = .init(arena);
        for (0..n_req) |i| {
            var one_body: std.Io.Writer.Allocating = .init(arena);
            const bw = &one_body.writer;
            switch (si) {
                0 => try bw.print("{{\"name\":\"Ada Lovelace {d}\",\"email\":\"ada{d}@example.com\",\"age\":{d},\"password\":\"correct horse battery staple {d}\"}}", .{ i, i, 36 + i, i }),
                1 => {
                    try bw.print("{{\"id\":\"order-{d}\",\"owner\":{{\"name\":\"Grace Hopper\",\"email\":\"grace@example.com\"}},\"items\":[", .{i});
                    for (0..10) |k| {
                        if (k != 0) try bw.writeByte(',');
                        try bw.print("{{\"sku\":\"SKU-{d:0>4}\",\"qty\":{d},\"price\":{d}.99}}", .{ k, k + 1, k });
                    }
                    try bw.writeAll("]}");
                },
                2 => try bw.print("{{\"name\":\"A\",\"email\":\"not-an-email\",\"age\":-{d},\"password\":\"correct horse battery staple {d}\"}}", .{ 5 + i, i }),
                else => try bw.print("{{\"email\":\"user{d}@example.com\",\"id\":\"550e8400-e29b-41d4-a716-4466554400{d:0>2}\",\"url\":\"https://example.com/path/{d}?x=1\"}}", .{ i, i, i }),
            }
            const body = one_body.written();
            d.bodies[si][i] = body;
            if (i != 0) try all.writer.writeByte(0);
            try all.writer.writeAll(body);
        }
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.json", .{shape}), .data = all.written() });
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

    var d: Data = try setup(arena, io, dir);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const use_fast = if (init.environ_map.get("BENCH_FAST")) |v| !std.mem.eql(u8, v, "0") else true;
    if (use_fast) try rustBuild(arena, io);
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    if (use_fast) try w.print("{s:<22} {s:>11} {s:>11} {s:>9}  net, vs cheapest (who)\n", .{ "", fast_names[0] ++ " ns", fast_names[1] ++ " ns", "ours/best" });
    try w.flush();
    var worst_fast: f64 = 0;
    var worst_fast_row: []const u8 = "";
    var worst_fast_who: []const u8 = "";
    var base_fast = [_]f64{ 0, 0 };
    var worst: f64 = 0;
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
        const info = wi % 2 == 0; // the decode_* twins
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        var fast = [_]bench.Side{ .{}, .{} };
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            if (use_fast) for (fast_names, 0..) |fname, fi| fast[fi].add(try fastRun(arena, io, abs, name, fname));
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ &d, wi }, true));
        }
        const gross = ours.best_ns / go.best_ns;
        // The decode twin is the cost both sides carry; what is left over
        // is validation itself.
        var net: f64 = std.math.nan(f64);
        var net_ok = false;
        if (info) {
            base_ours = ours.best_ns;
            base_ref = go.best_ns;
        } else if (base_ref != 0 and go.best_ns > base_ref) {
            net = (ours.best_ns - base_ours) / (go.best_ns - base_ref);
            net_ok = true;
        }
        const ratio = if (!info and !std.math.isNan(net)) net else gross;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(false), go.spread(false)));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(false), 100 * go.spread(false), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ " ++ ref_short });
        if (use_fast) {
            // net cost of each side = workload - its own decode twin; the
            // cheapest of the reference and the contenders is the yardstick
            const ours_cost = ours.best_ns - base_ours;
            var fastest_cost: f64 = if (net_ok) go.best_ns - base_ref else std.math.inf(f64);
            var fastest_who: []const u8 = ref_short;
            try w.print("{s:<22}", .{""});
            for (fast_names, 0..) |fname, fi| {
                try w.print(" {d:>11.0}", .{fast[fi].best_ns});
                max_spread = @max(max_spread, fast[fi].spread(false));
                if (fast[fi].count != ours.count) {
                    mismatch = true;
                    try w.print(" ({s}: {d} != ours {d})", .{ fname, fast[fi].count, ours.count });
                }
                if (info) {
                    base_fast[fi] = fast[fi].best_ns;
                } else if (base_fast[fi] != 0 and fast[fi].best_ns > base_fast[fi] and fast[fi].best_ns - base_fast[fi] < fastest_cost) {
                    fastest_cost = fast[fi].best_ns - base_fast[fi];
                    fastest_who = fast_cards[fi];
                }
            }
            if (!info and std.math.isFinite(fastest_cost)) {
                const ratio_fast = if (ours_cost > 0) ours_cost / fastest_cost else 0;
                if (ratio_fast > worst_fast) {
                    worst_fast = ratio_fast;
                    worst_fast_row = name;
                    worst_fast_who = fastest_who;
                }
                try w.print(" {d:>9.3}  ({s})\n", .{ ratio_fast, fastest_who });
            } else try w.writeAll("\n");
        }
        if (!info) {
            base_ours = 0;
            base_ref = 0;
            base_fast = .{ 0, 0 };
        }
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time (verdict = net of the decode_* twin); largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (use_fast) try w.print("worst vs fastest = {d:.2} (row {s}, {s})\n", .{ worst_fast, worst_fast_row, worst_fast_who });
    if (filters.len == 0) {
        if (use_fast)
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× {s} (measured <today>)\n", .{ best, worst, ref_card, worst_fast, worst_fast_who })
        else
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    }
    try w.flush();
    return 0;
}

// ---- the "fastest in the field" side ----

/// `cargo build --release --offline` of tools/rust_fast_bench.
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

/// `<exe> <work dir> <workload> <contender>` prints `name \t ns/op \t count`.
fn fastRun(arena: std.mem.Allocator, io: std.Io, abs: []const u8, name: []const u8, who: []const u8) !bench.Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ fast_rs_exe, abs, name, who } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed on {s}:\n{s}\n", .{ bench_name, who, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count };
}
