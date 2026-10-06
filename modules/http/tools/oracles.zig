// SPDX-License-Identifier: MIT

//! Two phases of `zig build interop-http` that judge this module's output by
//! Python implementations, and freeze what they accepted so the module's own
//! tests replay it with no Python (CONVENTIONS §9: a module is standalone
//! Zig; the anchor lives here, the replay in `src/`).
//!
//!   --phase problem   CPython `json.loads` parses every `problem.write`
//!                     document (RFC 9457 member types); `detail` must decode
//!                     exactly as CPython's `decode("utf-8", "replace")` (the
//!                     Unicode "maximal subpart" substitution) over Unicode
//!                     table 3-8, overlongs, surrogates, every C0 control and
//!                     200 pseudo-random byte strings; the default title of
//!                     each status 100..599 is compared with `http.HTTPStatus`.
//!                     Teeth: CPython must refuse a raw control character and
//!                     raw invalid UTF-8. Writes `src/problem_oracle_vectors.zig`.
//!   --phase sse       Our server streams events, curl fetches them, and
//!                     sseclient-py and httpx-sse dispatch them; each must be
//!                     what the WHATWG §9.2.6 rules make of what we sent. Teeth:
//!                     the same stream with one event terminator removed must
//!                     fail. Writes `src/sse_oracle_vectors.zig`.
//!
//! Each phase writes its vectors to scratch and compares them with the
//! committed file; `--write` replaces the committed file instead. Needs
//! `python3` (problem) and the venv `~/.local/share/zig-libs/oracle-venvs/http`
//! with sseclient-py, httpx-sse and httpx (sse). It does not skip: running the
//! phase IS the request to consult the oracle.

const std = @import("std");
const http = @import("http");

const Writer = std.Io.Writer;
const Server = http.Server;

pub const scratch = ".zig-cache/interop-http";

/// A Zig string literal for `bytes`: printable ASCII as is, `\n` by name,
/// everything else `\xHH`.
fn zigStr(w: *Writer, bytes: []const u8) !void {
    try w.writeByte('"');
    for (bytes) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(c),
        else => try w.print("\\x{x:0>2}", .{c}),
    };
    try w.writeByte('"');
}

fn optStr(w: *Writer, s: ?[]const u8) !void {
    if (s) |v| try zigStr(w, v) else try w.writeAll("null");
}

const Ran = struct { code: u8, out: []u8 };

fn run(io: std.Io, arena: std.mem.Allocator, env: *const std.process.Environ.Map, argv: []const []const u8, cwd: []const u8) !Ran {
    const out_path = try std.fmt.allocPrint(arena, "{s}/stdout.txt", .{cwd});
    {
        const out = try std.Io.Dir.cwd().createFile(io, out_path, .{});
        defer out.close(io);
        var child = std.process.spawn(io, .{
            .argv = argv,
            .cwd = .{ .path = cwd },
            .environ_map = env,
            .stdin = .close,
            .stdout = .{ .file = out },
            .stderr = .inherit,
        }) catch |e| {
            std.debug.print("could not spawn {s} ({t}) -- the oracle is required, not optional\n", .{ argv[0], e });
            return error.NoOracle;
        };
        const term = try child.wait(io);
        const code: u8 = switch (term) {
            .exited => |c| c,
            else => 255,
        };
        return .{ .code = code, .out = try std.Io.Dir.cwd().readFileAlloc(io, out_path, arena, .limited(8 << 20)) };
    }
}

/// Compare the fresh vectors with the committed file, or replace it.
fn settle(io: std.Io, arena: std.mem.Allocator, name: []const u8, fresh: []const u8, write: bool) !bool {
    const committed = try std.fmt.allocPrint(arena, "modules/http/src/{s}", .{name});
    const tmp = try std.fmt.allocPrint(arena, "{s}/{s}", .{ scratch, name });
    // Written already in `zig fmt`'s layout (one item per line, no
    // alignment), so the committed file passes the pre-commit fmt check.
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = fresh });
    const formatted = fresh;
    if (write) {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = committed, .data = formatted });
        std.debug.print("{s}: written\n", .{committed});
        return true;
    }
    const want = std.Io.Dir.cwd().readFileAlloc(io, committed, arena, .limited(16 << 20)) catch "";
    if (std.mem.eql(u8, want, formatted)) {
        std.debug.print("{s} matches a fresh run -- OK\n", .{committed});
        return true;
    }
    std.debug.print("{s}: a fresh run differs -- NOT OK (diff {s} {s}; --write after review)\n", .{ committed, committed, tmp });
    return false;
}

// ── problem ─────────────────────────────────────────────────────────────

const problem_fixed = [_][]const u8{
    "",                                     "plain ASCII",                      "quote \" backslash \\ slash /",
    "\x00\x01\x02\x03\x04\x05\x06\x07",     "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", "\x10\x11\x12\x13\x14\x15\x16\x17",
    "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f", "line\u{2028}sep\u{2029}para",      "\u{1F600} emoji, \u{10FFFF} max",
    "\u{FEFF}bom",                          "\xc4\x8d\xc5\xa1 2-byte",
    "a\xF1\x80\x80\xE1\x80\xC2b", // Unicode table 3-8
    "\xC0\xAF\xE0\x80\xBF\xF0\x81\x82\x41", // overlongs
    "\xED\xA0\x80\xED\xBF\xBF\x41", // surrogates
    "\xF4\x90\x80\x80\x41", // > U+10FFFF
    "\xF5\xF8\xFC\xFE\xFF\x41", // never-valid lead bytes
    "\x80\xBF\x80", // lone continuations
    "\xC2", "\xE1\x80", "\xF1\x80\x80", // truncated at the end
    "\xE0\xA0", "\xF0\x90\x80", "\xED\x9F", // truncated, valid prefix
    "\xC2\x41\xE1\x80\x41", // a lead followed by ASCII
};

const problem_random = 200;

fn randomBytes(prng: *std.Random.DefaultPrng, buf: []u8) []const u8 {
    const r = prng.random();
    const len = r.uintLessThan(usize, buf.len);
    for (buf[0..len]) |*b| {
        b.* = switch (r.uintLessThan(u8, 8)) {
            0 => r.uintLessThan(u8, 0x80),
            1 => 0xC0 + r.uintLessThan(u8, 0x20),
            2 => 0xE0 + r.uintLessThan(u8, 0x10),
            3 => 0xF0 + r.uintLessThan(u8, 0x10),
            else => 0x80 + r.uintLessThan(u8, 0x40),
        };
    }
    return buf[0..len];
}

/// The `Problem` each input is written into — also what the replay writes.
pub fn problemFor(input: []const u8) http.problem.Problem {
    return .{ .type = "https://example.com/p", .status = 400, .detail = input, .instance = input };
}

const problem_checker =
    \\import json, sys
    \\from http import HTTPStatus
    \\if sys.argv[1] == "refuse":
    \\    for line in open("bad.jsonl", "rb").read().split(b"\n")[:-1]:
    \\        try:
    \\            json.loads(line.decode("utf-8"))
    \\        except Exception:
    \\            continue
    \\        print("ACCEPTED", line); sys.exit(1)
    \\    sys.exit(0)
    \\ins = [bytes.fromhex(h) for h in open("in.txt").read().split("\n")[:-1]]
    \\docs = open("docs.jsonl", "rb").read().split(b"\n")[:-1]
    \\types = {"type": str, "status": int, "title": str, "detail": str, "instance": str}
    \\bad = 0
    \\if len(ins) != len(docs): print("COUNT"); bad += 1
    \\for i, (b, d) in enumerate(zip(ins, docs)):
    \\    try:
    \\        o = json.loads(d.decode("utf-8"))
    \\    except Exception as e:
    \\        print("PARSE", i, e, file=sys.stderr); bad += 1; continue
    \\    for k, t in types.items():
    \\        if k in o and type(o[k]) is not t: print("TYPE", i, k, file=sys.stderr); bad += 1
    \\    if o.get("detail") != b.decode("utf-8", "replace"):
    \\        print("DETAIL", i, b.hex(), file=sys.stderr); bad += 1
    \\for code in range(100, 600):
    \\    if code in HTTPStatus._value2member_map_:
    \\        print("PHRASE", code, HTTPStatus(code).phrase)
    \\sys.exit(1 if bad else 0)
;

pub fn problemPhase(io: std.Io, gpa: std.mem.Allocator, arena: std.mem.Allocator, env: *const std.process.Environ.Map, write: bool) !bool {
    const dir = scratch ++ "/problem";
    try std.Io.Dir.cwd().createDirPath(io, dir);
    var inputs: std.ArrayList([]const u8) = .empty;
    for (problem_fixed) |f| try inputs.append(arena, f);
    var prng = std.Random.DefaultPrng.init(0x9457);
    var rbuf: [24]u8 = undefined;
    for (0..problem_random) |_| try inputs.append(arena, try arena.dupe(u8, randomBytes(&prng, &rbuf)));

    var ins: Writer.Allocating = .init(gpa);
    defer ins.deinit();
    var docs: Writer.Allocating = .init(gpa);
    defer docs.deinit();
    for (inputs.items) |input| {
        try ins.writer.print("{x}\n", .{input});
        try http.problem.write(&docs.writer, problemFor(input), .{});
        try docs.writer.writeByte('\n');
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = dir ++ "/in.txt", .data = ins.written() });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = dir ++ "/docs.jsonl", .data = docs.written() });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = dir ++ "/bad.jsonl", .data = "{\"type\":\"a\",\"detail\":\"x\x01y\"}\n{\"type\":\"a\",\"detail\":\"x\xC0y\"}\n{\"type\":\"a\",\"detail\":\"x\xED\xA0\x80y\"}\n" });

    const teeth = try run(io, arena, env, &.{ "python3", "-c", problem_checker, "refuse" }, dir);
    if (teeth.code != 0) {
        std.debug.print("problem: CPython accepted a malformed document -- the oracle has no teeth\n", .{});
        return false;
    }
    const checked = try run(io, arena, env, &.{ "python3", "-c", problem_checker, "check" }, dir);
    if (checked.code != 0) {
        std.debug.print("problem: CPython refused or misread our documents -- NOT OK\n", .{});
        return false;
    }

    var v: Writer.Allocating = .init(gpa);
    defer v.deinit();
    const w = &v.writer;
    try w.writeAll(
        \\// SPDX-License-Identifier: MIT
        \\// GENERATED by `zig build interop-http -- --phase problem --write` (modules/http/tools/oracles.zig)
        \\// -- do not hand-edit. CPython parsed every document below with `json.loads`, found each standard
        \\// member of its RFC 9457 type, and decoded `detail` exactly as `bytes.decode("utf-8", "replace")`
        \\// decodes the input; `phrases` is its `http.HTTPStatus` table. Replayed by `problem_oracle.zig`.
        \\
        \\/// `detail` and `instance` of each document (see `tools/oracles.zig` `problemFor`).
        \\pub const inputs = [_][]const u8{
        \\
    );
    for (inputs.items) |input| {
        try w.writeAll("    ");
        try zigStr(w, input);
        try w.writeAll(",\n");
    }
    try w.writeAll("};\n\n/// What `problem.write` produced for them, one document per line.\npub const docs = ");
    try zigStr(w, docs.written());
    try w.writeAll(";\n\npub const Phrase = struct { status: u16, phrase: []const u8 };\n\n/// CPython's `http.HTTPStatus` phrases.\npub const phrases = [_]Phrase{\n");
    var pl = std.mem.splitScalar(u8, checked.out, '\n');
    while (pl.next()) |line| {
        if (!std.mem.startsWith(u8, line, "PHRASE ")) continue;
        const rest = line["PHRASE ".len..];
        const sp = std.mem.indexOfScalar(u8, rest, ' ').?;
        try w.print("    .{{ .status = {s}, .phrase = ", .{rest[0..sp]});
        try zigStr(w, rest[sp + 1 ..]);
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n");
    return settle(io, arena, "problem_oracle_vectors.zig", v.written(), write);
}

// ── sse ─────────────────────────────────────────────────────────────────

const SseCase = struct {
    ev: http.sse.Event,
    /// What a client must dispatch for it (WHATWG §9.2.6).
    want_type: []const u8 = "message",
    want_data: []const u8,
};

const ten_k = "0123456789abcdef" ** 640;

const sse_cases = [_]SseCase{
    .{ .ev = .{ .data = "hello" }, .want_data = "hello" },
    .{ .ev = .{ .data = "" }, .want_data = "" },
    .{ .ev = .{ .data = "a\nb" }, .want_data = "a\nb" },
    .{ .ev = .{ .data = "a\r\nb" }, .want_data = "a\nb" },
    .{ .ev = .{ .data = "a\rb" }, .want_data = "a\nb" },
    .{ .ev = .{ .data = "a\n" }, .want_data = "a\n" },
    .{ .ev = .{ .data = "\n" }, .want_data = "\n" },
    .{ .ev = .{ .data = "a\n\nb" }, .want_data = "a\n\nb" },
    .{ .ev = .{ .data = "a\r\n\r\nb\r" }, .want_data = "a\n\nb\n" },
    .{ .ev = .{ .data = " one leading space" }, .want_data = " one leading space" },
    .{ .ev = .{ .data = "  two" }, .want_data = "  two" },
    .{ .ev = .{ .data = "trailing " }, .want_data = "trailing " },
    .{ .ev = .{ .data = "data: looks like a field" }, .want_data = "data: looks like a field" },
    .{ .ev = .{ .data = ": looks like a comment" }, .want_data = ": looks like a comment" },
    .{ .ev = .{ .data = "\x00nul\x00" }, .want_data = "\x00nul\x00" },
    .{ .ev = .{ .data = "\xc5\xa1 \u{1F600} \u{FEFF}" }, .want_data = "\xc5\xa1 \u{1F600} \u{FEFF}" },
    .{ .ev = .{ .data = ten_k }, .want_data = ten_k },
    .{ .ev = .{ .event = "tick", .data = "x" }, .want_type = "tick", .want_data = "x" },
    .{ .ev = .{ .event = " spaced", .data = "x" }, .want_type = " spaced", .want_data = "x" },
    .{ .ev = .{ .event = "a:b", .data = "x" }, .want_type = "a:b", .want_data = "x" },
    .{ .ev = .{ .event = "", .data = "x" }, .want_data = "x" },
    .{ .ev = .{ .id = "7", .data = "x" }, .want_data = "x" },
    .{ .ev = .{ .data = "keeps id 7" }, .want_data = "keeps id 7" },
    .{ .ev = .{ .id = " spaced id", .data = "x" }, .want_data = "x" },
    .{ .ev = .{ .id = "", .data = "x" }, .want_data = "x" },
    .{ .ev = .{ .retry = 3000, .data = "x" }, .want_data = "x" },
    .{ .ev = .{ .retry = 0, .event = "last", .id = "z", .data = "end" }, .want_type = "last", .want_data = "end" },
};

/// Comments sent after the last event: a client dispatches nothing for them.
const sse_comments = [_][]const u8{ "keep-alive", "", " spaced" };

fn wantId(i: usize) []const u8 {
    var id: []const u8 = "";
    for (sse_cases[0 .. i + 1]) |c| if (c.ev.id) |v| {
        id = v;
    };
    return id;
}

/// A client's departure from §9.2.6 at event `at` (`>= sse_cases.len`: an
/// event dispatched where the rules dispatch none).
const SseDivergence = struct { lib: []const u8, at: usize, why: []const u8 };

const sse_divergences = [_]SseDivergence{
    .{ .lib = "httpx-sse", .at = sse_cases.len, .why = "a block holding only a comment leaves the data buffer empty, and dispatch then returns without an event (WHATWG §9.2.6, dispatch step 1); httpx-sse dispatches an empty message for it" },
    .{ .lib = "httpx-sse", .at = sse_cases.len + 1, .why = "as above (an empty comment)" },
    .{ .lib = "httpx-sse", .at = sse_cases.len + 2, .why = "as above" },
};

fn sseHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    _ = req;
    var es = try http.sse.EventStream.start(rw);
    for (sse_cases) |c| try es.send(c.ev);
    for (sse_comments) |c| try es.comment(c);
}

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

/// One JSON line per dispatched event: `[lib, type, data, last_id, retry]`.
/// sseclient-py's `id` is the event's own id field, carried forward here as
/// the spec's `lastEventId`; its `retry` is a string.
const sse_parser =
    \\import json
    \\import httpx, httpx_sse, sseclient
    \\raw = open("stream.bin", "rb").read()
    \\last = ""
    \\for e in sseclient.SSEClient(iter([raw])).events():
    \\    if e.id is not None: last = e.id
    \\    print(json.dumps(["sseclient", e.event, e.data, last, None if e.retry is None else int(e.retry)]))
    \\r = httpx.Response(200, headers={"content-type": "text/event-stream"}, content=raw)
    \\for e in httpx_sse.EventSource(r).iter_sse():
    \\    print(json.dumps(["httpx-sse", e.event, e.data, e.id, e.retry]))
;

/// Unlisted differences between the clients' events and §9.2.6.
fn sseCompare(arena: std.mem.Allocator, out: []const u8, quiet: bool) !usize {
    var bad: usize = 0;
    var used = [_]bool{false} ** sse_divergences.len;
    for ([_][]const u8{ "sseclient", "httpx-sse" }) |lib| {
        var at: usize = 0;
        var lines = std.mem.splitScalar(u8, out, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const v = try std.json.parseFromSliceLeaky([5]std.json.Value, arena, line, .{});
            if (!std.mem.eql(u8, v[0].string, lib)) continue;
            defer at += 1;
            const ok = at < sse_cases.len and blk: {
                const c = sse_cases[at];
                const want_retry: ?i64 = if (c.ev.retry) |r| r else null;
                const got_retry: ?i64 = if (v[4] == .integer) v[4].integer else null;
                break :blk std.mem.eql(u8, v[1].string, c.want_type) and
                    std.mem.eql(u8, v[2].string, c.want_data) and
                    std.mem.eql(u8, v[3].string, wantId(at)) and
                    want_retry == got_retry;
            };
            const listed = for (sse_divergences, 0..) |d, i| {
                if (std.mem.eql(u8, d.lib, lib) and d.at == at) break i;
            } else null;
            if (listed) |i| used[i] = true;
            if (ok == (listed == null)) continue;
            bad += 1;
            if (!quiet) std.debug.print("sse {s} event {d}: {s}: {s}\n", .{ lib, at, if (ok) "listed but agrees" else "differs", line });
        }
        if (at < sse_cases.len) {
            if (!quiet) std.debug.print("sse {s}: dispatched {d} of {d} events\n", .{ lib, at, sse_cases.len });
            bad += 1;
        }
    }
    for (sse_divergences, used) |d, u| if (!u) {
        if (!quiet) std.debug.print("sse: divergence {s}@{d} names no event\n", .{ d.lib, d.at });
        bad += 1;
    };
    return bad;
}

pub fn ssePhase(io: std.Io, gpa: std.mem.Allocator, arena: std.mem.Allocator, env: *const std.process.Environ.Map, write: bool) !bool {
    const dir = scratch ++ "/sse";
    try std.Io.Dir.cwd().createDirPath(io, dir);
    const home = env.get("HOME") orelse return error.NoHome;
    const python = try std.fmt.allocPrint(arena, "{s}/.local/share/zig-libs/oracle-venvs/http/bin/python", .{home});

    var server = Server.init(io, gpa, .{ .handler = sseHandler });
    defer server.deinit();
    try server.bind();
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer {
        server.shutdown();
        thread.join();
    }
    const url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/events", .{server.boundAddress().getPort()});
    const fetched = try run(io, arena, env, &.{ "curl", "-sS", "--max-time", "20", "-o", "stream.bin", url }, dir);
    if (fetched.code != 0) return error.CurlFailed;
    const stream = try std.Io.Dir.cwd().readFileAlloc(io, dir ++ "/stream.bin", arena, .limited(4 << 20));

    const parsed = try run(io, arena, env, &.{ python, "-c", sse_parser }, dir);
    if (parsed.code != 0) return error.SseParserFailed;
    if (try sseCompare(arena, parsed.out, false) != 0) {
        std.debug.print("sse: the clients dispatched something §9.2.6 does not -- NOT OK\n", .{});
        return false;
    }
    // Teeth: one event terminator removed (events 0 and 1 merge) must fail.
    const cut = std.mem.indexOf(u8, stream, "hello\n\n").? + "hello\n".len;
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = dir ++ "/stream.bin", .data = try std.mem.concat(arena, u8, &.{ stream[0..cut], stream[cut + 1 ..] }) });
    const broken = try run(io, arena, env, &.{ python, "-c", sse_parser }, dir);
    if (broken.code != 0 or try sseCompare(arena, broken.out, true) == 0) {
        std.debug.print("sse: a merged event went unnoticed -- the oracle has no teeth\n", .{});
        return false;
    }

    var v: Writer.Allocating = .init(gpa);
    defer v.deinit();
    const w = &v.writer;
    try w.writeAll(
        \\// SPDX-License-Identifier: MIT
        \\// GENERATED by `zig build interop-http -- --phase sse --write` (modules/http/tools/oracles.zig)
        \\// -- do not hand-edit. Our server streamed `events` then `comments`, curl fetched the stream,
        \\// and sseclient-py and httpx-sse dispatched exactly what WHATWG §9.2.6 makes of it (httpx-sse's
        \\// dispatch of comment-only blocks listed there). Replayed by `sse_oracle.zig`.
        \\
        \\const sse = @import("sse.zig");
        \\
        \\pub const events = [_]sse.Event{
        \\
    );
    for (sse_cases) |c| {
        try w.writeAll("    .{ .event = ");
        try optStr(w, c.ev.event);
        try w.writeAll(", .id = ");
        try optStr(w, c.ev.id);
        try w.writeAll(", .data = ");
        try zigStr(w, c.ev.data);
        if (c.ev.retry) |r| try w.print(", .retry = {d}", .{r});
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n\npub const comments = [_][]const u8{\n");
    for (sse_comments) |c| {
        try w.writeAll("    ");
        try zigStr(w, c);
        try w.writeAll(",\n");
    }
    try w.writeAll("};\n\n/// The response body curl received.\npub const stream = ");
    try zigStr(w, stream);
    try w.writeAll(";\n");
    return settle(io, arena, "sse_oracle_vectors.zig", v.written(), write);
}
