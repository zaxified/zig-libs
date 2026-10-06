// SPDX-License-Identifier: MIT

//! LIVE third-party decoders for `sse`: this module's server streams a
//! sequence of events (`EventStream.send` / `comment`, chunked, flushed per
//! event), curl fetches the stream, and two independent Python SSE clients —
//! sseclient-py (Apache-2.0) and httpx-sse (MIT), run from the venv in
//! `~/.local/share/zig-libs/oracle-venvs/http`, never read — parse it. Each
//! event they dispatch must be the one the WHATWG HTML "server-sent events"
//! parsing rules (§9.2.6) make of what we meant to send: its type, its data
//! (CR LF and lone CR become LF — the only line breaks SSE can carry), the
//! last event ID, the retry time. A client that departs from those rules is
//! listed below with the rule it breaks; a case that differs unlisted fails.
//!
//! Skips loudly when curl or the venv is missing:
//!   V=~/.local/share/zig-libs/oracle-venvs/http
//!   python3 -m venv $V && $V/bin/pip install sseclient-py httpx-sse httpx

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const Server = @import("Server.zig");
const sse = @import("sse.zig");
const testkit = @import("testkit");
const Writer = std.Io.Writer;

const Case = struct {
    /// What we send.
    ev: sse.Event,
    /// What a client must dispatch for it (WHATWG §9.2.6).
    want_type: []const u8 = "message",
    want_data: []const u8,
};

const ten_k = "0123456789abcdef" ** 640;

const cases = [_]Case{
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

/// The last event ID a client holds after case `i` (§9.2.6: an `id` field
/// sets it, for this and every later event, until another sets it again).
fn wantId(i: usize) []const u8 {
    var id: []const u8 = "";
    for (cases[0 .. i + 1]) |c| if (c.ev.id) |v| {
        id = v;
    };
    return id;
}

/// Comments sent after the last event: a client dispatches nothing for them.
const comments = [_][]const u8{ "keep-alive", "", " spaced" };

fn sseHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    _ = req;
    var es = try sse.EventStream.start(rw);
    for (cases) |c| try es.send(c.ev);
    for (comments) |c| try es.comment(c);
}

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

/// Parse `stream.bin` with both clients; one JSON line per dispatched event:
/// `[lib, type, data, last_id, retry]`. sseclient-py's `id` is the event's own
/// id field, not the last event ID, so it is carried forward here (the spec's
/// `lastEventId`); its `retry` is a string.
const parser =
    \\import json, sys
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

/// A client's departure from §9.2.6 at case index `at` (`at == cases.len` and
/// beyond: events it dispatched where the spec dispatches none), and the rule.
const ClientDivergence = struct { lib: []const u8, at: usize, why: []const u8 };

const client_divergences = [_]ClientDivergence{
    .{ .lib = "httpx-sse", .at = cases.len, .why = "a block holding only a comment leaves the data buffer empty, and dispatch then returns without an event (WHATWG §9.2.6, dispatch step 1); httpx-sse dispatches an empty message for it" },
    .{ .lib = "httpx-sse", .at = cases.len + 1, .why = "as above (an empty comment)" },
    .{ .lib = "httpx-sse", .at = cases.len + 2, .why = "as above" },
};

fn run(io: std.Io, dir: std.Io.Dir, argv: []const []const u8, out_name: ?[]const u8) !u8 {
    const out: ?std.Io.File = if (out_name) |n| try dir.createFile(io, n, .{}) else null;
    defer if (out) |f| f.close(io);
    var child = std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .dir = dir },
        .stdin = .ignore,
        .stdout = if (out) |f| .{ .file = f } else .ignore,
        .stderr = .ignore,
    }) catch return testkit.skip("LIVE http sse interop: cannot run `{s}`", .{argv[0]});
    return switch (try child.wait(io)) {
        .exited => |code| code,
        else => 255,
    };
}

test "LIVE sse: sseclient-py and httpx-sse dispatch the events the WHATWG rules make of our stream" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = testkit.getEnv("HOME") orelse return testkit.skip("LIVE http sse interop: no $HOME", .{});
    var py_buf: [512]u8 = undefined;
    const python = try std.fmt.bufPrint(&py_buf, "{s}/.local/share/zig-libs/oracle-venvs/http/bin/python", .{home});
    std.Io.Dir.cwd().access(io, python, .{}) catch return testkit.skip(
        "LIVE http sse interop: no oracle venv. V=~/.local/share/zig-libs/oracle-venvs/http; python3 -m venv $V && $V/bin/pip install sseclient-py httpx-sse httpx",
        .{},
    );

    var server = Server.init(io, gpa, .{ .handler = sseHandler });
    server.bind() catch |err| {
        server.deinit();
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer {
        server.shutdown();
        thread.join();
        server.deinit();
    }
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/events", .{server.boundAddress().getPort()});
    try testing.expectEqual(@as(u8, 0), try run(io, tmp.dir, &.{ "curl", "-sS", "--max-time", "20", "-o", "stream.bin", url }, null));
    try testing.expectEqual(@as(u8, 0), try run(io, tmp.dir, &.{ python, "-c", parser }, "events.jsonl"));
    const out = try tmp.dir.readFileAlloc(io, "events.jsonl", gpa, .limited(4 << 20));
    defer gpa.free(out);

    try testing.expectEqual(@as(usize, 0), try compare(gpa, out, false));

    // Teeth: the same stream with one event terminator removed (events 0 and
    // 1 merge) must fail the comparison.
    const stream = try tmp.dir.readFileAlloc(io, "stream.bin", gpa, .limited(4 << 20));
    defer gpa.free(stream);
    const cut = std.mem.indexOf(u8, stream, "hello\n\n").? + "hello\n".len;
    const broken = try std.mem.concat(gpa, u8, &.{ stream[0..cut], stream[cut + 1 ..] });
    defer gpa.free(broken);
    try tmp.dir.writeFile(io, .{ .sub_path = "stream.bin", .data = broken });
    try testing.expectEqual(@as(u8, 0), try run(io, tmp.dir, &.{ python, "-c", parser }, "events.jsonl"));
    const out2 = try tmp.dir.readFileAlloc(io, "events.jsonl", gpa, .limited(4 << 20));
    defer gpa.free(out2);
    try testing.expect(try compare(gpa, out2, true) > 0);
}

/// Compare the clients' events (`out`) with what §9.2.6 dispatches; the
/// number of unlisted differences. `quiet` for the negative control.
fn compare(gpa: std.mem.Allocator, out: []const u8, quiet: bool) !usize {
    var bad: usize = 0;
    var used = [_]bool{false} ** client_divergences.len;
    for ([_][]const u8{ "sseclient", "httpx-sse" }) |lib| {
        var at: usize = 0;
        var lines = std.mem.splitScalar(u8, out, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const parsed = try std.json.parseFromSlice([5]std.json.Value, gpa, line, .{});
            defer parsed.deinit();
            const v = parsed.value;
            if (!std.mem.eql(u8, v[0].string, lib)) continue;
            defer at += 1;
            const ok = at < cases.len and blk: {
                const c = cases[at];
                const want_retry: ?i64 = if (c.ev.retry) |r| r else null;
                const got_retry: ?i64 = if (v[4] == .integer) v[4].integer else null;
                break :blk std.mem.eql(u8, v[1].string, c.want_type) and
                    std.mem.eql(u8, v[2].string, c.want_data) and
                    std.mem.eql(u8, v[3].string, wantId(at)) and
                    want_retry == got_retry;
            };
            const listed = for (client_divergences, 0..) |d, i| {
                if (std.mem.eql(u8, d.lib, lib) and d.at == at) break i;
            } else null;
            if (listed) |i| used[i] = true;
            if (ok == (listed == null)) continue;
            bad += 1;
            if (!quiet) std.debug.print("sse {s} event {d}: {s}: {s}\n", .{ lib, at, if (ok) "listed but agrees" else "differs", line });
        }
        if (at < cases.len) {
            if (!quiet) std.debug.print("sse {s}: dispatched {d} of {d} events\n", .{ lib, at, cases.len });
            bad += 1;
        }
    }
    for (client_divergences, used) |d, u| if (!u) {
        if (!quiet) std.debug.print("sse: divergence {s}@{d} names no event\n", .{ d.lib, d.at });
        bad += 1;
    };
    return bad;
}
