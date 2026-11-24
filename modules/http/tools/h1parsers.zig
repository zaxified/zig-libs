// SPDX-License-Identifier: MIT

//! `zig build interop-http -- --phase h1parsers`: this module's HTTP/1.1
//! request framing against two parsers better known than it is, on the same
//! raw wires -- hyper 1.11 (the server connection under axum and most of Rust's
//! web stack; `tools/rust_fast_bench/src/bin/h1_verdicts.rs`, the crate tree of
//! the bench, built `--offline`) and llhttp 9.4 (the parser of Node.js and
//! uvicorn, through the Python package `httptools` 0.9.0 in the http oracle venv;
//! `tools/h1_llhttp.py`).
//!
//! The wires: every wire of the Go oracle (`src/go_oracle_vectors.zig`, read
//! from there so they stay one table) plus the smuggling-shaped ones of
//! `extraCases` (Content-Length with Transfer-Encoding in obfuscated shapes,
//! obs-fold, bare LF and bare CR, bad chunk sizes and trailers, over-long
//! lines). For each, the verdict of each parser is what the Go oracle records
//! for net/http: the requests that reached the handler (method, target, body)
//! and whether the server answered an error itself.
//!
//! The verdicts are frozen into `src/h1_parsers_vectors.zig` and replayed with
//! no Rust and no Python by `src/h1_parsers.zig`, which judges every
//! disagreement. Without `--write` the phase takes the verdicts again and
//! fails when they differ from the committed file. Needs `cargo` with the
//! crate tree in its offline cache and the venv `~/.local/share/zig-libs/oracle-venvs/http`
//! with `httptools`.

const std = @import("std");

const Writer = std.Io.Writer;

const scratch = ".zig-cache/interop-http";
const go_vectors = "modules/http/src/go_oracle_vectors.zig";
const out_path = "modules/http/src/h1_parsers_vectors.zig";
const rust_dir = "modules/http/tools/rust_fast_bench";
const hyper_exe = rust_dir ++ "/target/release/h1_verdicts";

const Case = struct { id: []const u8, wire: []const u8 };

const Call = struct { method: []const u8, target: []const u8, body: ?[]const u8 };

const Verdict = struct { reject: u16, calls: []const Call };

// ── the wires ──────────────────────────────────────────────────────────────

/// Every `.id`/`.wire` pair of the Go oracle's h1 table.
fn goCases(io: std.Io, arena: std.mem.Allocator) ![]const Case {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, go_vectors, arena, .limited(8 << 20));
    var out: std.ArrayList(Case) = .empty;
    var in_h1 = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "pub const h1 = ")) {
            in_h1 = true;
            continue;
        }
        if (!in_h1) continue;
        if (std.mem.startsWith(u8, line, "};")) break;
        const id_at = std.mem.find(u8, line, ".id = \"") orelse continue;
        const id_start = id_at + ".id = \"".len;
        const id_end = std.mem.findScalarPos(u8, line, id_start, '"') orelse continue;
        const w_at = std.mem.find(u8, line, ".wire = ") orelse continue;
        const lit_start = w_at + ".wire = ".len;
        // The literal ends at the first unescaped quote.
        var i = lit_start + 1;
        while (i < line.len and line[i] != '"') : (i += if (line[i] == '\\') @as(usize, 2) else 1) {}
        const wire = try std.zig.string_literal.parseAlloc(arena, line[lit_start .. i + 1]);
        try out.append(arena, .{ .id = line[id_start..id_end], .wire = wire });
    }
    return out.items;
}

fn fill(arena: std.mem.Allocator, c: u8, n: usize) []const u8 {
    const b = arena.alloc(u8, n) catch @panic("OOM");
    @memset(b, c);
    return b;
}

fn cat(arena: std.mem.Allocator, parts: []const []const u8) []const u8 {
    return std.mem.concat(arena, u8, parts) catch @panic("OOM");
}

const head = "POST /p HTTP/1.1\r\nHost: x\r\n";

/// The smuggling-shaped wires the Go oracle does not have.
fn extraCases(arena: std.mem.Allocator) ![]const Case {
    const a = arena;
    var out: std.ArrayList(Case) = .empty;
    const t = struct {
        fn add(l: *std.ArrayList(Case), al: std.mem.Allocator, id: []const u8, wire: []const u8) void {
            l.append(al, .{ .id = id, .wire = wire }) catch @panic("OOM");
        }
    }.add;
    // ── Content-Length with Transfer-Encoding, obfuscated ──
    t(&out, a, "te-space-before-colon-cl", head ++ "Transfer-Encoding : chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n");
    t(&out, a, "te-tab-before-colon-cl", head ++ "Transfer-Encoding\t: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n");
    t(&out, a, "te-obs-fold-chunked-cl", head ++ "Transfer-Encoding:\r\n chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n");
    t(&out, a, "te-lowercase-names-cl", head ++ "transfer-encoding: chunked\r\ncontent-length: 4\r\n\r\n0\r\n\r\n");
    t(&out, a, "te-chunked-cl-zero", head ++ "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n");
    t(&out, a, "te-identity-then-chunked", head ++ "Transfer-Encoding: identity, chunked\r\n\r\n0\r\n\r\n");
    t(&out, a, "te-chunked-then-identity", head ++ "Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n");
    t(&out, a, "te-chunked-semicolon", head ++ "Transfer-Encoding: chunked;q=1\r\n\r\n0\r\n\r\n");
    t(&out, a, "te-cl-hidden-request", head ++ "Transfer-Encoding: chunked\r\nContent-Length: 53\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\nX-Pad: ab\r\n\r\n");
    t(&out, a, "cl-te-hidden-request", head ++ "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: x\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n");
    t(&out, a, "cl-zero-then-pipelined-get", head ++ "Content-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n");
    t(&out, a, "cl-short-then-pipelined-get", head ++ "Content-Length: 2\r\n\r\nabGET /admin HTTP/1.1\r\nHost: x\r\n\r\n");
    t(&out, a, "cl-list-differ", head ++ "Content-Length: 4, 5\r\n\r\nabcde");
    t(&out, a, "cl-negative-zero", head ++ "Content-Length: -0\r\n\r\n");
    t(&out, a, "cl-two-fields-differ-pipelined", head ++ "Content-Length: 3\r\nContent-Length: 5\r\n\r\nabcdeGET / HTTP/1.1\r\nHost: x\r\n\r\n");
    // ── obs-fold ──
    t(&out, a, "obs-fold-tab", "GET / HTTP/1.1\r\nHost: x\r\nX-A: b\r\n\tc\r\n\r\n");
    t(&out, a, "obs-fold-after-host", "GET / HTTP/1.1\r\nHost: x\r\n y\r\n\r\n");
    t(&out, a, "obs-fold-in-content-length", head ++ "Content-Length: 4\r\n 5\r\n\r\nabcde");
    t(&out, a, "obs-fold-empty-fold-line", "GET / HTTP/1.1\r\nHost: x\r\nX-A: b\r\n \r\n c\r\n\r\n");
    // ── bare LF and bare CR ──
    t(&out, a, "lf-after-request-line-only", "GET / HTTP/1.1\nHost: x\r\n\r\n");
    t(&out, a, "lf-after-host-only", "GET / HTTP/1.1\r\nHost: x\nX-A: b\r\n\r\n");
    t(&out, a, "lf-ends-head", "GET / HTTP/1.1\r\nHost: x\r\n\n");
    t(&out, a, "cr-ends-head", "GET / HTTP/1.1\r\nHost: x\r\n\r");
    t(&out, a, "bare-cr-inside-request-line", "GET /a\rb HTTP/1.1\r\nHost: x\r\n\r\n");
    t(&out, a, "chunk-size-bare-lf", head ++ "Transfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n");
    t(&out, a, "chunk-data-end-bare-lf", head ++ "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\n0\r\n\r\n");
    t(&out, a, "chunk-last-bare-lf", head ++ "Transfer-Encoding: chunked\r\n\r\n0\n\n");
    t(&out, a, "chunk-size-bare-cr", head ++ "Transfer-Encoding: chunked\r\n\r\n5\rhello\r\n0\r\n\r\n");
    // ── chunk sizes, extensions and trailers ──
    t(&out, a, "chunk-size-negative", head ++ "Transfer-Encoding: chunked\r\n\r\n-5\r\nhello\r\n0\r\n\r\n");
    t(&out, a, "chunk-size-g", head ++ "Transfer-Encoding: chunked\r\n\r\ng\r\nhello\r\n0\r\n\r\n");
    t(&out, a, "chunk-size-inner-space", head ++ "Transfer-Encoding: chunked\r\n\r\n5 5\r\nhello\r\n0\r\n\r\n");
    t(&out, a, "chunk-size-high-byte", head ++ "Transfer-Encoding: chunked\r\n\r\n5\xff\r\nhello\r\n0\r\n\r\n");
    t(&out, a, "chunk-ext-bare-cr", head ++ "Transfer-Encoding: chunked\r\n\r\n5;a\rb\r\nhello\r\n0\r\n\r\n");
    t(&out, a, "chunk-ext-no-name", head ++ "Transfer-Encoding: chunked\r\n\r\n5;\r\nhello\r\n0\r\n\r\n");
    t(&out, a, "chunk-trailer", head ++ "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-T: v\r\n\r\n");
    t(&out, a, "chunk-trailer-then-pipelined-get", head ++ "Transfer-Encoding: chunked\r\n\r\n0\r\nX-T: v\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n");
    t(&out, a, "chunk-trailer-unterminated", head ++ "Transfer-Encoding: chunked\r\n\r\n0\r\nX-T: v\r\n");
    t(&out, a, "chunk-trailer-obs-fold", head ++ "Transfer-Encoding: chunked\r\n\r\n0\r\nX-T: v\r\n w\r\n\r\n");
    t(&out, a, "chunk-trailer-bad-line", head ++ "Transfer-Encoding: chunked\r\n\r\n0\r\nnot a header\r\n\r\n");
    t(&out, a, "chunk-trailer-content-length", head ++ "Transfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 5\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n");
    t(&out, a, "chunk-last-without-final-crlf", head ++ "Transfer-Encoding: chunked\r\n\r\n0\r\n");
    t(&out, a, "chunk-data-lf-for-crlf", head ++ "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\n");
    t(&out, a, "chunk-pipelined-after-last", head ++ "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n");
    // ── over-long lines and too many headers ──
    t(&out, a, "header-value-20k", cat(a, &.{ "GET / HTTP/1.1\r\nHost: x\r\nX-A: ", fill(a, 'a', 20000), "\r\n\r\n" }));
    t(&out, a, "header-name-20k", cat(a, &.{ "GET / HTTP/1.1\r\nHost: x\r\n", fill(a, 'a', 20000), ": b\r\n\r\n" }));
    t(&out, a, "target-20k", cat(a, &.{ "GET /", fill(a, 'a', 20000), " HTTP/1.1\r\nHost: x\r\n\r\n" }));
    t(&out, a, "target-9k", cat(a, &.{ "GET /", fill(a, 'a', 9000), " HTTP/1.1\r\nHost: x\r\n\r\n" }));
    t(&out, a, "method-20k", cat(a, &.{ fill(a, 'M', 20000), " / HTTP/1.1\r\nHost: x\r\n\r\n" }));
    {
        var w: std.Io.Writer.Allocating = .init(a);
        w.writer.writeAll("GET / HTTP/1.1\r\nHost: x\r\n") catch @panic("OOM");
        for (0..300) |i| w.writer.print("X-H{d}: v\r\n", .{i}) catch @panic("OOM");
        w.writer.writeAll("\r\n") catch @panic("OOM");
        t(&out, a, "headers-300", w.written());
        var w2: std.Io.Writer.Allocating = .init(a);
        w2.writer.writeAll("GET / HTTP/1.1\r\nHost: x\r\n") catch @panic("OOM");
        for (0..20) |i| w2.writer.print("X-H{d}: {s}\r\n", .{ i, fill(a, 'v', 3500) }) catch @panic("OOM");
        w2.writer.writeAll("\r\n") catch @panic("OOM");
        t(&out, a, "head-70k-in-20-headers", w2.written());
    }
    return out.items;
}

// ── running the oracles ────────────────────────────────────────────────────

fn hex(w: *Writer, bytes: []const u8) !void {
    for (bytes) |b| try w.print("{x:0>2}", .{b});
}

fn unhex(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    const out = try arena.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn runCmd(io: std.Io, arena: std.mem.Allocator, env: *const std.process.Environ.Map, argv: []const []const u8) ![]const u8 {
    const r = std.process.run(arena, io, .{
        .argv = argv,
        .environ_map = env,
        .stdout_limit = .limited(64 << 20),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(600), .clock = .awake } },
    }) catch |err| {
        std.debug.print("h1parsers: could not run {s} ({t})\n", .{ argv[0], err });
        return error.OracleFailed;
    };
    if (r.term != .exited or r.term.exited != 0) {
        std.debug.print("h1parsers: {s} failed:\n{s}\n", .{ argv[0], r.stderr });
        return error.OracleFailed;
    }
    return r.stdout;
}

/// One output line per case, in the order of `cases`.
fn parseVerdicts(arena: std.mem.Allocator, cases: []const Case, out: []const u8) ![]Verdict {
    const res = try arena.alloc(Verdict, cases.len);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, out, "\n"), '\n');
    for (cases, res) |c, *v| {
        const line = lines.next() orelse return error.MissingVerdict;
        var f = std.mem.splitScalar(u8, line, '\t');
        const id = f.next().?;
        if (!std.mem.eql(u8, id, c.id)) return error.VerdictOutOfOrder;
        const reject = try std.fmt.parseInt(u16, f.next().?, 10);
        const n = try std.fmt.parseInt(usize, f.next().?, 10);
        const calls = try arena.alloc(Call, n);
        for (calls) |*call| {
            call.method = try unhex(arena, f.next().?);
            call.target = try unhex(arena, f.next().?);
            const b = f.next().?;
            call.body = if (std.mem.eql(u8, b, "-")) null else if (std.mem.eql(u8, b, "+")) "" else try unhex(arena, b);
        }
        v.* = .{ .reject = reject, .calls = calls };
    }
    return res;
}

// ── the vectors file ───────────────────────────────────────────────────────

/// A Zig string expression for `bytes`: printable ASCII as is, runs of 64 or
/// more of one byte as `rep(c, n)`, the rest `\xHH`.
fn zigStr(w: *Writer, bytes: []const u8) !void {
    var i: usize = 0;
    var open = false;
    var first = true;
    while (i < bytes.len) {
        var j = i;
        while (j < bytes.len and bytes[j] == bytes[i]) j += 1;
        if (j - i >= 64) {
            if (open) {
                try w.writeByte('"');
                open = false;
            }
            if (!first) try w.writeAll(" ++ ");
            try w.print("rep({d}, {d})", .{ bytes[i], j - i });
            first = false;
            i = j;
            continue;
        }
        if (!open) {
            if (!first) try w.writeAll(" ++ ");
            try w.writeByte('"');
            open = true;
            first = false;
        }
        const c = bytes[i];
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(c),
            else => try w.print("\\x{x:0>2}", .{c}),
        }
        i += 1;
    }
    if (open) try w.writeByte('"');
    if (first) try w.writeAll("\"\"");
}

fn writeVerdict(w: *Writer, v: Verdict) !void {
    // No trailing commas: `zig fmt` keeps such a list on one line.
    try w.print(".{{ .reject = {d}, .calls = &.{{", .{v.reject});
    if (v.calls.len > 1) try w.writeByte(' ');
    for (v.calls, 0..) |c, i| {
        try w.writeAll(if (i == 0) ".{ .method = " else ", .{ .method = ");
        try zigStr(w, c.method);
        try w.writeAll(", .target = ");
        try zigStr(w, c.target);
        try w.writeAll(", .body = ");
        if (c.body) |b| try zigStr(w, b) else try w.writeAll("null");
        try w.writeAll(" }");
    }
    if (v.calls.len > 1) try w.writeByte(' ');
    try w.writeAll("} }");
}

fn render(arena: std.mem.Allocator, cases: []const Case, hyper: []const Verdict, llhttp: []const Verdict) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll("// SPDX-License-Identifier: MIT\n" ++
        "// GENERATED by modules/http/tools/h1parsers.zig (hyper 1.11.0, llhttp 9.4.3 through httptools 0.9.0) -- do not hand-edit.\n" ++
        "//! What hyper's HTTP/1.1 server connection and llhttp's request parser do with the Go oracle's wires\n" ++
        "//! and the smuggling-shaped ones of `tools/h1parsers.zig`, replayed by `h1_parsers.zig`.\n" ++
        "//! `reject`: the first non-200 status hyper answered, 400 for an llhttp parse error in a head, 0\n" ++
        "//! for none. `calls`: the requests that reached the handler, `body` null when it could not be read\n" ++
        "//! to its end.\n\n" ++
        "pub const hyper_version = \"1.11.0\";\npub const llhttp_version = \"9.4.3 (httptools 0.9.0)\";\n\n" ++
        "fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {\n    return &@as([n]u8, @splat(c));\n}\n\n" ++
        "pub const Call = struct { method: []const u8, target: []const u8, body: ?[]const u8 };\n" ++
        "pub const Verdict = struct { reject: u16, calls: []const Call };\n" ++
        "pub const Case = struct { id: []const u8, wire: []const u8, hyper: Verdict, llhttp: Verdict };\n\n" ++
        "pub const cases = [_]Case{\n");
    for (cases, hyper, llhttp) |c, h, l| {
        try w.writeAll("    .{ .id = ");
        try zigStr(w, c.id);
        try w.writeAll(", .wire = ");
        try zigStr(w, c.wire);
        try w.writeAll(", .hyper = ");
        try writeVerdict(w, h);
        try w.writeAll(", .llhttp = ");
        try writeVerdict(w, l);
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n");
    return aw.written();
}

pub fn phase(io: std.Io, arena: std.mem.Allocator, env: *std.process.Environ.Map, write: bool) !bool {
    const go = try goCases(io, arena);
    const extra = try extraCases(arena);
    const cases = try std.mem.concat(arena, Case, &.{ go, extra });
    std.debug.print("h1parsers: {d} wires ({d} from the Go oracle, {d} of ours)\n", .{ cases.len, go.len, extra.len });

    var cw: std.Io.Writer.Allocating = .init(arena);
    for (cases) |c| {
        try cw.writer.print("{s}\t", .{c.id});
        try hex(&cw.writer, c.wire);
        try cw.writer.writeByte('\n');
    }
    const cases_path = scratch ++ "/h1-cases.tsv";
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = cases_path, .data = cw.written() });

    // hyper: built from the bench's crate tree, offline.
    if (std.Io.Dir.cwd().access(io, hyper_exe, .{})) |_| {} else |_| {
        _ = try runCmd(io, arena, env, &.{ "cargo", "build", "--release", "--offline", "--bin", "h1_verdicts", "--manifest-path", rust_dir ++ "/Cargo.toml" });
    }
    const hyper_out = try runCmd(io, arena, env, &.{ hyper_exe, cases_path });
    const home = env.get("HOME") orelse return error.NoHome;
    const python = try arena.print("{s}/.local/share/zig-libs/oracle-venvs/http/bin/python", .{home});
    const llhttp_out = try runCmd(io, arena, env, &.{ python, "-I", "modules/http/tools/h1_llhttp.py", cases_path });

    const hyper = try parseVerdicts(arena, cases, hyper_out);
    const llhttp = try parseVerdicts(arena, cases, llhttp_out);
    const text = try render(arena, cases, hyper, llhttp);

    if (write) {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = text });
        std.debug.print("h1parsers: wrote {s} ({d} cases)\n", .{ out_path, cases.len });
        return true;
    }
    const old = std.Io.Dir.cwd().readFileAlloc(io, out_path, arena, .limited(32 << 20)) catch "";
    if (std.mem.eql(u8, old, text)) {
        std.debug.print("h1parsers: {d} cases, verdicts as committed -- OK\n", .{cases.len});
        return true;
    }
    const fresh = scratch ++ "/h1_parsers_vectors.fresh.zig";
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = fresh, .data = text });
    std.debug.print("h1parsers: a fresh run differs from {s} -- NOT OK\n  diff {s} {s}; a changed verdict needs reading before it is committed (--write)\n", .{ out_path, out_path, fresh });
    return false;
}
