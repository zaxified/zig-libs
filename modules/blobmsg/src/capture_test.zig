// SPDX-License-Identifier: MIT

//! The client against a REAL ubusd, in two forms.
//!
//! 1. **Replay** (always runs): `testdata/ubusd_capture.zig` holds the frames a real
//!    `ubusd` (OpenWrt ubus db20eff5, built from source, run as a black box) exchanged
//!    with the real `ubus` CLI and with a scripted provider, recorded by
//!    `tools/ubus_capture.py`. A replay daemon plays the daemon's side of one captured
//!    connection to our `Client` and checks that every request our client sends is
//!    BYTE-identical to the frame the real CLI sent in that spot. The replies are
//!    the real ones, so the client's parsing is checked against the daemon's bytes.
//! 2. **Live** (skips without a socket): when `BLOBMSG_UBUS_SOCKET` names a running
//!    ubusd's socket the tests below talk to it; `tools/ubus_capture.py
//!    --with-daemon -- <test binary>` starts a private one (and a provider object
//!    "probe"), see the tool's docstring. Every live test counts as skipped in CI,
//!    which has no ubusd.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const blobmsg = @import("root.zig");
const codec = blobmsg.codec;
const Client = blobmsg.Client;
const Error = blobmsg.Error;
const cap = @import("testdata/ubusd_capture.zig");

fn find(name: []const u8) *const cap.Capture {
    for (&cap.captures) |*c| if (std.mem.eql(u8, c.name, name)) return c;
    std.debug.panic("capture {s} missing from testdata/ubusd_capture.zig", .{name});
}

fn unhex(gpa: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex.len / 2);
    errdefer gpa.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// The connection of the capture that carries the CLI's HELLO (the provider's
/// own connection, conn 1, has none in the capture).
fn cliConn(c: *const cap.Capture) u8 {
    for (c.frames) |f| if (f.dir == .d2c and f.hex.len >= 4 and std.mem.eql(u8, f.hex[0..4], "0000")) return f.conn;
    std.debug.panic("capture {s} has no HELLO", .{c.name});
}

const Part = struct { name: []const u8, conn: ?u8 = null };

/// The frames of one connection, from one or more captures, in order.
fn script(gpa: std.mem.Allocator, parts: []const Part) ![]cap.Frame {
    var out: std.ArrayList(cap.Frame) = .empty;
    errdefer out.deinit(gpa);
    var first_conn: ?u8 = null;
    for (parts) |p| {
        const c = find(p.name);
        const conn = p.conn orelse first_conn orelse cliConn(c);
        if (first_conn == null) first_conn = conn;
        for (c.frames) |f| if (f.conn == conn) try out.append(gpa, f);
    }
    return out.toOwnedSlice(gpa);
}

fn sleepMs(ms: u64) void {
    const ts: linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * 1_000_000) };
    _ = linux.nanosleep(&ts, null);
}

// ── the replay daemon ───────────────────────────────────────────────────────

fn rawWrite(fd: i32, bytes: []const u8) bool {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.sendto(fd, bytes[off..].ptr, bytes.len - off, linux.MSG.NOSIGNAL, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => {},
            else => return false,
        }
    }
    return true;
}

fn rawRead(fd: i32, buf: []u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const rc = linux.read(fd, buf[off..].ptr, buf.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) return false else {
                off += rc;
            },
            .INTR => {},
            else => return false,
        }
    }
    return true;
}

const Replay = struct {
    listen_fd: i32,
    path_buf: [96]u8 = undefined,
    path: [:0]const u8 = undefined,
    /// Plain connections (HELLO only, held open) accepted before the scripted one.
    pre_conns: u8 = 0,
    frames: []const cap.Frame,
    /// Index of the first c2d frame the client did not send as the real CLI did.
    mismatch: ?usize = null,
    played: usize = 0,
    /// Close the connection right after the script instead of staying up.
    hang_up: bool = false,
    /// The client sent something after the script ended (seen by `finish`).
    extra: bool = false,
    thread: ?std.Thread = null,

    fn init(r: *Replay, tag: []const u8, frames: []const cap.Frame, pre_conns: u8) !void {
        r.* = .{ .listen_fd = -1, .frames = frames, .pre_conns = pre_conns };
        r.path = try std.fmt.bufPrintSentinel(&r.path_buf, "/tmp/zl-bm-cap-{d}-{s}.sock", .{ linux.getpid(), tag }, 0);
        _ = linux.unlink(r.path.ptr);
        const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
        r.listen_fd = @intCast(rc);
        errdefer _ = linux.close(r.listen_fd);
        var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
        @memcpy(addr.path[0..r.path.len], r.path);
        const alen: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + r.path.len + 1);
        if (linux.errno(linux.bind(r.listen_fd, @ptrCast(&addr), alen)) != .SUCCESS) return error.BindFailed;
        if (linux.errno(linux.listen(r.listen_fd, 4)) != .SUCCESS) return error.ListenFailed;
        r.thread = try std.Thread.spawn(.{}, serve, .{r});
    }

    fn deinit(r: *Replay) void {
        if (r.thread) |t| {
            _ = linux.shutdown(r.listen_fd, linux.SHUT.RDWR); // wakes a blocked accept
            t.join();
            r.thread = null;
        }
        _ = linux.close(r.listen_fd);
        _ = linux.unlink(r.path.ptr);
    }

    /// Join (the client side is done) and require the script to have been played
    /// to its end with every client frame byte-identical.
    fn finish(r: *Replay) !void {
        if (r.thread) |t| {
            t.join();
            r.thread = null;
        }
        try testing.expectEqual(@as(?usize, null), r.mismatch);
        try testing.expectEqual(r.frames.len, r.played);
        try testing.expect(!r.extra); // no frame the real CLI did not send
    }

    fn serve(r: *Replay) void {
        const gpa = std.heap.page_allocator; // global-alloc-ok: test-only replay daemon thread body, not the published module
        var held: [4]i32 = @splat(-1);
        defer for (held) |f| if (f >= 0) {
            _ = linux.close(f);
        };
        const tv = linux.timeval{ .sec = 5, .usec = 0 };
        var i: u8 = 0;
        while (i < r.pre_conns) : (i += 1) {
            const rc = linux.accept(r.listen_fd, null, null);
            if (linux.errno(rc) != .SUCCESS) return;
            held[i] = @intCast(rc);
            const hello = codec.encodeMessage(gpa, codec.MSG.HELLO, 0, 50, &.{}) catch return;
            defer gpa.free(hello);
            if (!rawWrite(held[i], hello)) return;
        }
        const rc = linux.accept(r.listen_fd, null, null);
        if (linux.errno(rc) != .SUCCESS) return;
        const fd: i32 = @intCast(rc);
        held[3] = fd;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
        for (r.frames, 0..) |f, idx| {
            const want = unhex(gpa, f.hex) catch return;
            defer gpa.free(want);
            switch (f.dir) {
                .d2c => if (!rawWrite(fd, want)) return,
                .c2d => if (want.len == 0) { // any one client frame
                    var hdr: [codec.msghdr_len + 4]u8 = undefined;
                    if (!rawRead(fd, &hdr)) return;
                    const n = std.mem.readInt(u32, hdr[codec.msghdr_len..][0..4], .big) & codec.LEN_MASK;
                    if (n < 4 or n > 4096) return;
                    var rest: [4096]u8 = undefined;
                    if (!rawRead(fd, rest[0 .. n - 4])) return;
                } else {
                    const got = gpa.alloc(u8, want.len) catch return;
                    defer gpa.free(got);
                    if (!rawRead(fd, got) or !std.mem.eql(u8, got, want)) {
                        r.mismatch = idx;
                        return;
                    }
                },
            }
            r.played = idx + 1;
        }
        if (r.hang_up) return;
        // Stay up until the client lets go (or a bound passes).
        var one: [1]u8 = undefined;
        if (rawRead(fd, &one)) r.extra = true;
    }
};

fn drain(es: anytype, out: *std.ArrayList(u8), lines: usize) !void {
    var tries: usize = 0;
    while (std.mem.count(u8, out.items, "\n") < lines and tries < 600) : (tries += 1) {
        _ = try es.poll(out);
        if (std.mem.count(u8, out.items, "\n") < lines) sleepMs(5);
    }
}

// ── facts the captures pin (what used to be inferred) ──────────────────────

fn lastFrame(c: *const cap.Capture, conn: u8, dir: cap.Dir) []const u8 {
    var hex: []const u8 = "";
    for (c.frames) |f| if (f.conn == conn and f.dir == dir) {
        hex = f.hex;
    };
    return hex;
}

fn payloadOf(gpa: std.mem.Allocator, hex: []const u8) ![]u8 {
    const raw = try unhex(gpa, hex);
    defer gpa.free(raw);
    return gpa.dupe(u8, raw[codec.msghdr_len + 4 ..]);
}

fn statusOfHex(gpa: std.mem.Allocator, hex: []const u8) !?i32 {
    const p = try payloadOf(gpa, hex);
    defer gpa.free(p);
    var it: codec.AttrIterator = .{ .buf = p };
    var code: ?i32 = null;
    while (try it.next()) |a| if (a.id == codec.ATTR.STATUS) {
        code = std.mem.readInt(i32, a.data[0..4], .big);
    };
    return code;
}

test "capture facts: the closing STATUS of a LOOKUP and of ADD_OBJECT / register / send always carry a code" {
    const gpa = testing.allocator;
    // LOOKUP: 0 after the entries (with and without a pattern), 4 for no match.
    for ([_]struct { []const u8, i32 }{ .{ "lookup_all", 0 }, .{ "lookup_match", 0 }, .{ "lookup_nomatch", 4 } }) |c| {
        const cp = find(c[0]);
        const conn = cliConn(cp);
        try testing.expectEqual(@as(?i32, c[1]), try statusOfHex(gpa, lastFrame(cp, conn, .d2c)));
    }
    // listen: ADD_OBJECT answered DATA(OBJID) + STATUS(0), register answered STATUS(0).
    const reg = find("listen_register");
    var statuses: usize = 0;
    for (reg.frames) |f| if (f.dir == .d2c) {
        if (try statusOfHex(gpa, f.hex)) |code| {
            try testing.expectEqual(@as(i32, 0), code);
            statuses += 1;
        }
    };
    try testing.expectEqual(@as(usize, 2), statuses);
    // The refusals of an ordinary user: 6 (permission denied) for register and send, 2 for a named object.
    try testing.expectEqual(@as(?i32, 6), try statusOfHex(gpa, lastFrame(find("denied_listen"), 1, .d2c)));
    try testing.expectEqual(@as(?i32, 6), try statusOfHex(gpa, lastFrame(find("denied_send"), 2, .d2c)));
    try testing.expectEqual(@as(?i32, 2), try statusOfHex(gpa, lastFrame(find("denied_add_named"), 9, .d2c)));
    // A provider's non-zero return code reaches the caller as the completion STATUS (9).
    try testing.expectEqual(@as(?i32, 9), try statusOfHex(gpa, lastFrame(find("call_fail"), cliConn(find("call_fail")), .d2c)));
}

test "capture: `ubus -t 0` waits past the CLI's default timeout; this client refuses 0 (a named parity gap)" {
    // call_t0_long: a provider that answers after 33 s was waited for with `-t 0` and the result
    // printed; call_default_long: the same call without -t gave up with "Request timed out" (the
    // CLI's default is 30 s); call_t1_slow: `-t 1` gives up at 1 s. So 0 is "no limit".
    // This module bounds every call by design: `Options` 0 is `Unsupported`. That is a gap
    // against `ubus -t 0`, not parity; a caller wanting a long call passes a large value.
    try testing.expectEqualStrings("{\n\t\"msg\": \"s\"\n}\n", find("call_t0_long").cli_stdout);
    try testing.expectEqualStrings("", find("call_default_long").cli_stdout);
    try testing.expect(std.mem.find(u8, find("call_default_long").cli_stderr, "Request timed out") != null);
    try testing.expect(std.mem.find(u8, find("call_t1_slow").cli_stderr, "Request timed out") != null);
    try testing.expectError(Error.Unsupported, Client.openWith(testing.allocator, "/nonexistent", .{ .call_timeout_ms = 0 }));
}

test "replay: waitFor's LOOKUP is byte-identical to the real CLI's and finds the object; listen with two patterns registers twice" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    {
        const sc = try script(gpa, &.{.{ .name = "lookup_match" }});
        defer gpa.free(sc);
        var rp: Replay = undefined;
        try rp.init("waitfor", sc, 0);
        defer rp.deinit();
        var c = try Client.open(gpa, rp.path);
        try c.waitFor(&.{"probe"}, 500);
        c.close();
        try rp.finish();
    }
    // `ubus listen foo bar`: ADD_OBJECT, then one `register` per pattern (seq 2 and 3), each answered STATUS 0.
    const sc = try script(gpa, &.{.{ .name = "listen_two_register" }});
    defer gpa.free(sc);
    var rp: Replay = undefined;
    try rp.init("listen2", sc, 1);
    defer rp.deinit();
    var c = try Client.open(gpa, rp.path);
    var es = try c.subscribeMany(&.{ "foo", "bar" });
    es.close();
    c.close();
    try rp.finish();
}

// ── replay: list / invoke / sendEvent / subscribe / subscribeObject / monitor ─

test "replay: list against the real LOOKUP bytes (all, one match, no match)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    for ([_]struct { []const u8, ?[]const u8, bool }{
        .{ "lookup_all", null, true },
        .{ "lookup_match", "probe", true },
        .{ "lookup_nomatch", "nosuch", false },
    }) |t| {
        const sc = try script(gpa, &.{.{ .name = t[0] }});
        defer gpa.free(sc);
        var rp: Replay = undefined;
        try rp.init(t[0], sc, 0);
        defer rp.deinit();
        var c = try Client.open(gpa, rp.path);
        if (t[2]) {
            const objs = try c.list(t[1]);
            defer blobmsg.freeObjects(gpa, objs);
            try testing.expectEqual(@as(usize, 1), objs.len);
            try testing.expectEqualStrings("probe", objs[0].name);
            try testing.expectEqualStrings("{\"echo\":{\"msg\":3},\"fail\":{},\"slow\":{},\"slowlong\":{},\"notify\":{}}", objs[0].signature_json.?);
            try testing.expectEqual(@as(i32, 0), c.last_status);
        } else {
            try testing.expectError(Error.NotFound, c.list(t[1]));
            try testing.expectEqual(@as(i32, 4), c.last_status);
        }
        c.close();
        try rp.finish();
    }
}

test "replay: invoke against the real INVOKE bytes (result, provider failure, unknown object)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    {
        const sc = try script(gpa, &.{.{ .name = "call_echo" }});
        defer gpa.free(sc);
        var rp: Replay = undefined;
        try rp.init(&"echo".*, sc, 0);
        defer rp.deinit();
        var c = try Client.open(gpa, rp.path);
        const out = try c.invoke("probe", "echo", "{\"msg\":\"hi\"}");
        defer gpa.free(out);
        try testing.expectEqualStrings("{\"msg\":\"hi\"}", out);
        c.close();
        try rp.finish();
    }
    {
        const sc = try script(gpa, &.{.{ .name = "call_fail" }});
        defer gpa.free(sc);
        var rp: Replay = undefined;
        try rp.init(&"fail".*, sc, 0);
        defer rp.deinit();
        var c = try Client.open(gpa, rp.path);
        try testing.expectError(Error.UbusError, c.invoke("probe", "fail", null));
        try testing.expectEqual(@as(i32, 9), c.last_status);
        c.close();
        try rp.finish();
    }
    {
        const sc = try script(gpa, &.{.{ .name = "call_noobj" }});
        defer gpa.free(sc);
        var rp: Replay = undefined;
        try rp.init(&"noobj".*, sc, 0);
        defer rp.deinit();
        var c = try Client.open(gpa, rp.path);
        try testing.expectError(Error.NotFound, c.invoke("nosuch", "x", null));
        c.close();
        try rp.finish();
    }
}

test "replay: sendEvent is byte-identical to the real `ubus send`, accepted and refused" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    for ([_]struct { []const u8, []const u8 }{
        .{ "send_no_listener", "{\"a\":1}" },
        .{ "send_to_listener", "{\"a\":1,\"b\":\"x\"}" },
    }) |t| {
        const sc = try script(gpa, &.{.{ .name = t[0] }});
        defer gpa.free(sc);
        var rp: Replay = undefined;
        try rp.init(t[0], sc, 0);
        defer rp.deinit();
        var c = try Client.open(gpa, rp.path);
        try c.sendEvent("foo", t[1]);
        c.close();
        try rp.finish();
    }
    // An ordinary user is refused with 6.
    const sc = try script(gpa, &.{.{ .name = "denied_send" }});
    defer gpa.free(sc);
    var rp: Replay = undefined;
    try rp.init("denied-send", sc, 0);
    defer rp.deinit();
    var c = try Client.open(gpa, rp.path);
    try testing.expectError(Error.UbusError, c.sendEvent("foo", "{\"a\":1}"));
    try testing.expectEqual(@as(i32, 6), c.last_status);
    c.close();
    try rp.finish();
}

test "replay: subscribe (events) is byte-identical to the real `ubus listen *`, then an event arrives; refused for an ordinary user" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    // The listener's connection of the capture, then the event the daemon delivered to it
    // when the real CLI ran `send foo {"a":1,"b":"x"}` (conn 1 there is the listener).
    const sc = try script(gpa, &.{ .{ .name = "listen_register", .conn = 1 }, .{ .name = "send_to_listener", .conn = 1 } });
    defer gpa.free(sc);
    var rp: Replay = undefined;
    try rp.init("listen", sc, 1);
    defer rp.deinit();
    var c = try Client.open(gpa, rp.path);
    var es = try c.subscribe(null);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try drain(&es, &out, 1);
    try testing.expectEqualStrings("{\"foo\":{\"a\":1,\"b\":\"x\"}}\n", out.items);
    es.close();
    c.close();
    try rp.finish();

    const dn = try script(gpa, &.{.{ .name = "denied_listen" }});
    defer gpa.free(dn);
    var rp2: Replay = undefined;
    try rp2.init("denied-listen", dn, 1);
    defer rp2.deinit();
    var c2 = try Client.open(gpa, rp2.path);
    try testing.expectError(Error.UbusError, c2.subscribe(null));
    try testing.expectEqual(@as(i32, 6), c2.last_status);
    c2.close();
    try rp2.finish();
}

test "replay: subscribeObject is byte-identical to the real `ubus subscribe`, answers notifications like it, sees the target go" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const sc = try script(gpa, &.{
        .{ .name = "subscribe_setup", .conn = 2 },
        .{ .name = "subscribe_notify", .conn = 2 },
        .{ .name = "subscribe_notify2", .conn = 2 },
        .{ .name = "subscribe_target_gone", .conn = 2 },
    });
    defer gpa.free(sc);
    var rp: Replay = undefined;
    try rp.init("subobj", sc, 1);
    defer rp.deinit();
    var c = try Client.open(gpa, rp.path);
    var os = try c.subscribeObject("probe");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try drain(&os, &out, 2);
    // The real CLI printed `{ "tick": {"n":5,"s":"v"} }` for the same frames.
    try testing.expectEqualStrings("{\"tick\":{\"n\":5,\"s\":\"v\"}}\n{\"tock\":{\"k\":\"w\"}}\n", out.items);
    var tries: usize = 0;
    while (!os.target_gone and tries < 400) : (tries += 1) {
        _ = try os.poll(&out);
        sleepMs(5);
    }
    try testing.expect(os.target_gone);
    try testing.expectEqual(@as(u32, 0), os.malformed);
    os.close();
    c.close();
    try rp.finish(); // both STATUS answers the client sent matched the real CLI's bytes
}

test "replay: subscribeObject of a missing object is NotFound, like the real CLI" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const sc = try script(gpa, &.{.{ .name = "subscribe_nosuch" }});
    defer gpa.free(sc);
    var rp: Replay = undefined;
    try rp.init("subnone", sc, 1);
    defer rp.deinit();
    var c = try Client.open(gpa, rp.path);
    try testing.expectError(Error.NotFound, c.subscribeObject("nosuch"));
    try testing.expectEqual(@as(i32, 4), c.last_status);
    c.close();
    try rp.finish();
}

fn lineFields(line: []const u8) struct { send: bool, client: u32, peer: u32, kind: []const u8, json: []const u8 } {
    // `-> 944ce1b6 #00000003         status: {"status":0}`
    const send = std.mem.startsWith(u8, line, "->");
    const client = std.fmt.parseInt(u32, line[3..11], 16) catch 0;
    const peer = std.fmt.parseInt(u32, line[13..21], 16) catch 0;
    var i: usize = 21;
    while (line[i] == ' ') i += 1;
    const colon = std.mem.indexOfScalarPos(u8, line, i, ':').?;
    return .{ .send = send, .client = client, .peer = peer, .kind = line[i..colon], .json = line[colon + 2 ..] };
}

/// JSON equality where integers compare modulo 2^32 (the real CLI prints ids as signed).
fn sameJson(x: std.json.Value, y: std.json.Value) bool {
    switch (x) {
        .integer => |a| return y == .integer and (@as(u32, @truncate(@as(u64, @bitCast(a)))) == @as(u32, @truncate(@as(u64, @bitCast(y.integer))))),
        .string => |s| return y == .string and std.mem.eql(u8, s, y.string),
        .bool => |b| return y == .bool and y.bool == b,
        .array => |arr| {
            if (y != .array or y.array.items.len != arr.items.len) return false;
            for (arr.items, y.array.items) |p, q| if (!sameJson(p, q)) return false;
            return true;
        },
        .object => |o| {
            if (y != .object or y.object.count() != o.count()) return false;
            var it = o.iterator();
            while (it.next()) |e| {
                const other = y.object.get(e.key_ptr.*) orelse return false;
                if (!sameJson(e.value_ptr.*, other)) return false;
            }
            return true;
        },
        else => return false,
    }
}

test "replay: monitor is byte-identical to the real `ubus monitor` request and says what the CLI printed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const mon = find("monitor");
    const sc = try script(gpa, &.{.{ .name = "monitor" }});
    defer gpa.free(sc);
    var rp: Replay = undefined;
    try rp.init("monitor", sc, 1);
    defer rp.deinit();
    var c = try Client.open(gpa, rp.path);
    var ms = try c.monitor();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    // The CLI's output, line by line.
    var cli_lines: std.ArrayList([]const u8) = .empty;
    defer cli_lines.deinit(gpa);
    var lit = std.mem.splitScalar(u8, mon.cli_stdout, '\n');
    while (lit.next()) |l| if (l.len > 0) try cli_lines.append(gpa, l);
    try testing.expect(cli_lines.items.len >= 10);
    try drain(&ms, &out, cli_lines.items.len);

    var ours = std.mem.splitScalar(u8, out.items, '\n');
    var n: usize = 0;
    while (ours.next()) |l| {
        if (l.len == 0) continue;
        if (n >= cli_lines.items.len) break;
        const cf = lineFields(cli_lines.items[n]);
        var mine = try std.json.parseFromSlice(std.json.Value, gpa, l, .{});
        defer mine.deinit();
        const o = mine.value.object;
        try testing.expectEqual(cf.send, o.get("send").?.bool);
        try testing.expectEqual(@as(i64, cf.client), o.get("client").?.integer);
        try testing.expectEqual(@as(i64, cf.peer), o.get("peer").?.integer);
        try testing.expectEqualStrings(cf.kind, o.get("type").?.string);
        var theirs = try std.json.parseFromSlice(std.json.Value, gpa, cf.json, .{});
        defer theirs.deinit();
        try testing.expect(sameJson(o.get("message").?, theirs.value));
        n += 1;
    }
    try testing.expectEqual(cli_lines.items.len, n);
    try testing.expectEqual(@as(u32, 0), ms.malformed);
    ms.close();
    c.close();
    try rp.finish();
}

// ── live: a real ubusd (BLOBMSG_UBUS_SOCKET), skipped without ──────────────────

fn liveSocket() ?[]const u8 {
    if (builtin.os.tag != .linux) return null;
    return std.testing.environ.getPosix("BLOBMSG_UBUS_SOCKET");
}

test "live: list, unknown object, waitFor timeout, status codes (skips without BLOBMSG_UBUS_SOCKET)" {
    const path = liveSocket() orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    var c = try Client.open(gpa, path);
    defer c.close();
    const all = try c.list(null);
    defer blobmsg.freeObjects(gpa, all);
    // The tool's provider "probe" is there when the harness started it; a bare ubusd has none.
    try testing.expectError(Error.NotFound, c.list("zl.nosuch"));
    try testing.expectEqual(@as(i32, 4), c.last_status);
    try testing.expectError(Error.NotFound, c.invoke("zl.nosuch", "x", null));
    try testing.expectError(Error.Timeout, c.waitFor(&.{"zl.nosuch"}, 120));
    try testing.expectError(Error.NotFound, c.subscribeObject("zl.nosuch"));
    try testing.expectEqual(@as(i32, 4), c.last_status);
}

test "live: sendEvent reaches subscribe, and monitor taps both (skips without BLOBMSG_UBUS_SOCKET)" {
    const path = liveSocket() orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    var c = try Client.open(gpa, path);
    defer c.close();
    var es = try c.subscribe("zl.live"); // a named socket is a promise: a refusal FAILS
    defer es.close();
    var ms = try c.monitor();
    defer ms.close();
    try c.sendEvent("zl.live", "{\"n\":7}");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try drain(&es, &out, 1);
    try testing.expectEqualStrings("{\"zl.live\":{\"n\":7}}\n", out.items);
    var mon: std.ArrayList(u8) = .empty;
    defer mon.deinit(gpa);
    var tries: usize = 0;
    while (std.mem.find(u8, mon.items, "\"method\":\"zl.live\"") == null and tries < 600) : (tries += 1) {
        _ = try ms.poll(&mon);
        sleepMs(5);
    }
    try testing.expect(std.mem.find(u8, mon.items, "\"method\":\"send\"") != null);
    try testing.expect(std.mem.find(u8, mon.items, "\"method\":\"zl.live\"") != null);
    try testing.expectEqual(@as(u32, 0), ms.malformed);
}

test "live: provider object probe: list, invoke, subscribeObject gets its notification (skips without the tool's provider)" {
    const path = liveSocket() orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    var c = try Client.open(gpa, path);
    defer c.close();
    const probe = try c.list("probe"); // the tool starts the provider; without it this FAILS
    defer blobmsg.freeObjects(gpa, probe);
    try testing.expectEqualStrings("probe", probe[0].name);
    const echoed = try c.invoke("probe", "echo", "{\"msg\":\"hi\"}");
    defer gpa.free(echoed);
    try testing.expectEqualStrings("{\"msg\":\"hi\"}", echoed);
    try testing.expectError(Error.UbusError, c.invoke("probe", "fail", null));
    try testing.expectEqual(@as(i32, 9), c.last_status);

    var os = try c.subscribeObject("probe");
    defer os.close();
    const r = try c.invoke("probe", "notify", null); // the provider notifies its subscribers
    gpa.free(r);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try drain(&os, &out, 1);
    try testing.expectEqualStrings("{\"tick\":{\"n\":5,\"s\":\"v\"}}\n", out.items);
}

// ── hostile daemon through the two new verbs ──────────────────────────────────

const Hostile = struct {
    arena: std.heap.ArenaAllocator,
    frames: std.ArrayList(cap.Frame) = .empty,

    fn init() Hostile {
        return .{ .arena = std.heap.ArenaAllocator.init(testing.allocator) };
    }
    fn deinit(h: *Hostile) void {
        h.arena.deinit();
    }
    fn d2c(h: *Hostile, mtype: u8, seq: u16, peer: u32, children: []const u8) !void {
        const a = h.arena.allocator();
        const raw = try codec.encodeMessage(a, mtype, seq, peer, children);
        try h.rawHex(.d2c, raw);
    }
    fn rawHex(h: *Hostile, dir: cap.Dir, raw: []const u8) !void {
        const a = h.arena.allocator();
        const hex = try a.alloc(u8, raw.len * 2);
        _ = std.fmt.bufPrint(hex, "{x}", .{raw}) catch unreachable;
        try h.frames.append(a, .{ .conn = 2, .dir = dir, .hex = hex });
    }
    fn hello(h: *Hostile) !void {
        try h.d2c(codec.MSG.HELLO, 0, 7, &.{});
    }
    fn anyFrame(h: *Hostile) !void {
        try h.frames.append(h.arena.allocator(), .{ .conn = 2, .dir = .c2d, .hex = "" });
    }
    /// A message whose only child is the given raw attrs.
    fn status(h: *Hostile, seq: u16, code: ?u32, objid: ?u32) !void {
        const a = h.arena.allocator();
        var ch: std.ArrayList(u8) = .empty;
        if (code) |c| try codec.appendAttrU32(a, &ch, codec.ATTR.STATUS, c);
        if (objid) |o| try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, o);
        try h.d2c(codec.MSG.STATUS, seq, 0, ch.items);
    }
    fn data(h: *Hostile, seq: u16, objid: u32) !void {
        return h.dataPath(seq, "obj", objid);
    }
    fn dataPath(h: *Hostile, seq: u16, path: []const u8, objid: ?u32) !void {
        const a = h.arena.allocator();
        var ch: std.ArrayList(u8) = .empty;
        if (objid) |o| try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, o);
        try codec.appendAttrString(a, &ch, codec.ATTR.OBJPATH, path);
        try h.d2c(codec.MSG.DATA, seq, 0, ch.items);
    }
};

/// Run `verb` against the scripted hostile daemon (it hangs up after the script) and return its outcome.
fn hostileSubObj(h: *Hostile, tag: []const u8) anyerror!void {
    var rp: Replay = undefined;
    try rp.init(tag, h.frames.items, 1);
    rp.hang_up = true;
    defer rp.deinit();
    var c = try Client.openWith(testing.allocator, rp.path, .{ .call_timeout_ms = 300 });
    defer c.close();
    const r = c.subscribeObject("obj");
    last_status_seen = c.last_status;
    if (r) |st| {
        var s = st;
        s.close();
    } else |_| {}
    return if (r) |_| {} else |e| e;
}
var last_status_seen: i32 = 0;

test "hostile daemon: subscribeObject ends in a typed error at every step, none reads as absence or success" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const T = struct { name: []const u8, expect: Error, status: i32 = 0 };
    inline for ([_]T{
        .{ .name = "gone", .expect = Error.ShortRead },
        .{ .name = "cut-add-answer", .expect = Error.ShortRead },
        .{ .name = "add-no-code", .expect = Error.BadMessage },
        .{ .name = "add-no-objid", .expect = Error.BadMessage },
        .{ .name = "add-refused", .expect = Error.UbusError, .status = 6 },
        .{ .name = "lookup-4", .expect = Error.NotFound, .status = 4 },
        .{ .name = "lookup-no-entry", .expect = Error.NotFound, .status = 4 },
        .{ .name = "lookup-no-code", .expect = Error.BadMessage },
        .{ .name = "lookup-6", .expect = Error.UbusError, .status = 6 },
        .{ .name = "lookup-other-path", .expect = Error.NotFound, .status = 4 },
        .{ .name = "lookup-no-objid", .expect = Error.BadMessage },
        .{ .name = "lookup-empty-0", .expect = Error.NotFound, .status = 4 },
        .{ .name = "subscribe-6", .expect = Error.UbusError, .status = 6 },
        .{ .name = "subscribe-no-code", .expect = Error.BadMessage },
        .{ .name = "subscribe-cut", .expect = Error.ShortRead },
    }) |t| {
        var h = Hostile.init();
        defer h.deinit();
        try h.hello();
        try h.anyFrame(); // ADD_OBJECT
        if (comptime std.mem.eql(u8, t.name, "gone")) {
            // nothing more
        } else if (comptime std.mem.eql(u8, t.name, "cut-add-answer")) {
            try h.data(1, 5);
            const last = h.frames.pop().?;
            try h.frames.append(h.arena.allocator(), .{ .conn = 2, .dir = .d2c, .hex = last.hex[0 .. last.hex.len - 6] });
        } else if (comptime std.mem.eql(u8, t.name, "add-no-code")) {
            try h.data(1, 5);
            try h.status(1, null, null);
        } else if (comptime std.mem.eql(u8, t.name, "add-no-objid")) {
            try h.status(1, 0, null);
        } else if (comptime std.mem.eql(u8, t.name, "add-refused")) {
            try h.status(1, 6, null);
        } else {
            try h.data(1, 5);
            try h.status(1, 0, null);
            try h.anyFrame(); // LOOKUP
            if (comptime std.mem.eql(u8, t.name, "lookup-4")) {
                try h.data(2, 7);
                try h.status(2, 4, null);
            } else if (comptime std.mem.eql(u8, t.name, "lookup-no-entry")) {
                try h.status(2, 4, null);
            } else if (comptime std.mem.eql(u8, t.name, "lookup-no-code")) {
                try h.data(2, 7);
                try h.status(2, null, null);
            } else if (comptime std.mem.eql(u8, t.name, "lookup-6")) {
                try h.status(2, 6, null);
            } else if (comptime std.mem.eql(u8, t.name, "lookup-other-path")) {
                try h.dataPath(2, "other", 7); // an entry for another name is not ours
                try h.status(2, 0, null);
            } else if (comptime std.mem.eql(u8, t.name, "lookup-no-objid")) {
                try h.dataPath(2, "obj", null);
                try h.status(2, 0, null);
            } else if (comptime std.mem.eql(u8, t.name, "lookup-empty-0")) {
                try h.status(2, 0, null); // STATUS 0 and no entry at all
            } else {
                try h.data(2, 7);
                try h.status(2, 0, null);
                try h.anyFrame(); // SUBSCRIBE
                if (comptime std.mem.eql(u8, t.name, "subscribe-6")) {
                    try h.status(3, 6, null);
                } else if (comptime std.mem.eql(u8, t.name, "subscribe-no-code")) {
                    try h.status(3, null, null);
                } else {
                    try h.status(3, 0, null);
                    const last = h.frames.pop().?;
                    try h.frames.append(h.arena.allocator(), .{ .conn = 2, .dir = .d2c, .hex = last.hex[0 .. last.hex.len - 4] });
                }
            }
        }
        testing.expectError(t.expect, hostileSubObj(&h, t.name)) catch |e| {
            std.debug.print("hostile subscribeObject case {s}\n", .{t.name});
            return e;
        };
        try testing.expectEqual(t.status, last_status_seen);
    }
}

test "hostile daemon: subscribeObject stream - a frame cut by the hang-up is the stream ending, never an event; a wrong-addressed or garbled one is skipped and counted" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var h = Hostile.init();
    defer h.deinit();
    try h.hello();
    try h.anyFrame();
    try h.data(1, 5);
    try h.status(1, 0, null);
    try h.anyFrame();
    try h.data(2, 7);
    try h.status(2, 0, null);
    try h.anyFrame();
    try h.status(3, 0, null);
    const a = h.arena.allocator();
    // 1. an INVOKE for ANOTHER object (ignored, not answered), 2. one for us whose body is garbage
    //    (counted, answered INVALID_ARGUMENT = 2), 3. a good one cut in half.
    var ch: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 99);
    try codec.appendAttrString(a, &ch, codec.ATTR.METHOD, "x");
    try h.d2c(codec.MSG.INVOKE, 9, 1, ch.items);
    ch.clearRetainingCapacity();
    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 5);
    try codec.appendAttrString(a, &ch, codec.ATTR.METHOD, "bad");
    try codec.appendAttr(a, &ch, codec.ATTR.DATA, &.{ 0x85, 0, 0, 0x40, 1, 2, 3 }); // a blobmsg claiming 64 bytes
    try h.d2c(codec.MSG.INVOKE, 10, 2, ch.items);
    // the answer to it: STATUS 2 with OBJID, seq 10, peer 2
    var rep: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(a, &rep, codec.ATTR.STATUS, 2);
    try codec.appendAttrU32(a, &rep, codec.ATTR.OBJID, 5);
    const want = try codec.encodeMessage(a, codec.MSG.STATUS, 10, 2, rep.items);
    try h.rawHex(.c2d, want);
    ch.clearRetainingCapacity();
    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 5);
    try codec.appendAttrString(a, &ch, codec.ATTR.METHOD, "good");
    try codec.appendAttr(a, &ch, codec.ATTR.NO_REPLY, &.{1});
    try h.d2c(codec.MSG.INVOKE, 11, 3, ch.items);
    const cut = h.frames.pop().?;
    try h.frames.append(a, .{ .conn = 2, .dir = .d2c, .hex = cut.hex[0 .. cut.hex.len - 10] });

    var rp: Replay = undefined;
    try rp.init("hostile-obj-stream", h.frames.items, 1);
    rp.hang_up = true;
    defer rp.deinit();
    var c = try Client.openWith(gpa, rp.path, .{ .call_timeout_ms = 300 });
    defer c.close();
    var os = try c.subscribeObject("obj");
    defer os.close();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var closed = false;
    var tries: usize = 0;
    while (!closed and tries < 600) : (tries += 1) {
        closed = try os.poll(&out);
        if (!closed) sleepMs(5);
    }
    try testing.expect(closed);
    try testing.expectEqual(@as(usize, 0), out.items.len); // nothing was delivered as an event
    try testing.expectEqual(@as(u32, 1), os.malformed);
    try testing.expect(os.broken);
    try rp.finish();
}

test "hostile daemon: monitor - refused, no verdict, gone, and a stream of damaged frames is skipped and counted" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    for ([_][]const u8{ "gone", "refused", "no-code", "mixed" }) |name| {
        var h = Hostile.init();
        defer h.deinit();
        const a = h.arena.allocator();
        try h.hello();
        try h.anyFrame();
        if (std.mem.eql(u8, name, "refused")) try h.status(1, 6, null);
        if (std.mem.eql(u8, name, "no-code")) try h.status(1, null, null);
        if (std.mem.eql(u8, name, "mixed")) {
            // a damaged MONITOR frame (no client attr) BEFORE the verdict, then the verdict,
            // then a good frame and a cut one
            var ch: std.ArrayList(u8) = .empty;
            try codec.appendAttrU32(a, &ch, codec.MON.PEER, 3);
            try h.d2c(codec.MSG.MONITOR, 1, 0, ch.items);
            try h.status(1, 0, null);
            ch.clearRetainingCapacity();
            var inner: std.ArrayList(u8) = .empty;
            try codec.appendAttrU32(a, &inner, codec.ATTR.STATUS, 0);
            try codec.appendAttrU32(a, &ch, codec.MON.CLIENT, 0x55);
            try codec.appendAttrU32(a, &ch, codec.MON.PEER, 3);
            try codec.appendAttr(a, &ch, codec.MON.SEND, &.{1});
            try codec.appendAttrU32(a, &ch, codec.MON.SEQ, 1);
            try codec.appendAttrU32(a, &ch, codec.MON.TYPE, 1);
            try codec.appendAttr(a, &ch, codec.MON.DATA, inner.items);
            try h.d2c(codec.MSG.MONITOR, 2, 0, ch.items);
            try h.d2c(codec.MSG.MONITOR, 3, 0, ch.items);
            const cut = h.frames.pop().?;
            try h.frames.append(a, .{ .conn = 2, .dir = .d2c, .hex = cut.hex[0 .. cut.hex.len - 8] });
        }
        var rp: Replay = undefined;
        try rp.init("hostile-mon", h.frames.items, 1);
        rp.hang_up = true;
        defer rp.deinit();
        var c = try Client.openWith(gpa, rp.path, .{ .call_timeout_ms = 300 });
        defer c.close();
        if (std.mem.eql(u8, name, "mixed")) {
            var ms = try c.monitor();
            defer ms.close();
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(gpa);
            var closed = false;
            var tries: usize = 0;
            while (!closed and tries < 600) : (tries += 1) {
                closed = try ms.poll(&out);
                if (!closed) sleepMs(5);
            }
            try testing.expect(closed);
            try testing.expectEqual(@as(u32, 1), ms.malformed);
            // the one good frame, nothing of the cut one
            try testing.expectEqualStrings("{\"send\":true,\"client\":85,\"peer\":3,\"seq\":1,\"type\":\"status\",\"message\":{\"status\":0}}\n", out.items);
        } else if (std.mem.eql(u8, name, "refused")) {
            try testing.expectError(Error.UbusError, c.monitor());
            try testing.expectEqual(@as(i32, 6), c.last_status);
        } else if (std.mem.eql(u8, name, "no-code")) {
            try testing.expectError(Error.BadMessage, c.monitor());
        } else {
            try testing.expectError(Error.ShortRead, c.monitor());
        }
    }
}

test "hostile daemon: UNSUBSCRIBE counts only for our object and target; a garbled INVOKE is counted, answered only when it is ours" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var h = Hostile.init();
    defer h.deinit();
    const a = h.arena.allocator();
    try h.hello();
    try h.anyFrame();
    try h.data(1, 5); // our object id 5
    try h.status(1, 0, null);
    try h.anyFrame();
    try h.data(2, 7); // target 7
    try h.status(2, 0, null);
    try h.anyFrame();
    try h.status(3, 0, null);
    // UNSUBSCRIBE for another object and for another target: counted, not "gone"
    var ch: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 6);
    try codec.appendAttrU32(a, &ch, codec.ATTR.TARGET, 7);
    try h.d2c(codec.MSG.UNSUBSCRIBE, 4, 0, ch.items);
    ch.clearRetainingCapacity();
    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 5);
    try codec.appendAttrU32(a, &ch, codec.ATTR.TARGET, 8);
    try h.d2c(codec.MSG.UNSUBSCRIBE, 5, 0, ch.items);
    // a garbled INVOKE whose walk fails before any OBJID: counted, NOT answered
    try h.d2c(codec.MSG.INVOKE, 6, 1, &.{ 0x04, 0, 0, 0x7f, 1, 2, 3, 4 });
    // a garbled INVOKE already known to be ours (OBJID 5, no NO_REPLY): counted and answered 2
    ch.clearRetainingCapacity();
    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 5);
    try ch.appendSlice(a, &.{ 0x04, 0, 0, 0x7f, 1, 2, 3, 4 });
    try h.d2c(codec.MSG.INVOKE, 7, 2, ch.items);
    var rep: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(a, &rep, codec.ATTR.STATUS, 2);
    try codec.appendAttrU32(a, &rep, codec.ATTR.OBJID, 5);
    try h.rawHex(.c2d, try codec.encodeMessage(a, codec.MSG.STATUS, 7, 2, rep.items));
    // the right UNSUBSCRIBE
    ch.clearRetainingCapacity();
    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 5);
    try codec.appendAttrU32(a, &ch, codec.ATTR.TARGET, 7);
    try h.d2c(codec.MSG.UNSUBSCRIBE, 8, 0, ch.items);

    var rp: Replay = undefined;
    try rp.init("hostile-unsub", h.frames.items, 1);
    defer rp.deinit();
    var c = try Client.openWith(gpa, rp.path, .{ .call_timeout_ms = 300 });
    var os = try c.subscribeObject("obj");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var tries: usize = 0;
    while (!os.target_gone and tries < 600) : (tries += 1) {
        _ = try os.poll(&out);
        sleepMs(5);
    }
    try testing.expect(os.target_gone);
    try testing.expectEqual(@as(u32, 4), os.malformed); // two wrong UNSUBSCRIBEs + two garbled INVOKEs
    try testing.expectEqual(@as(usize, 0), out.items.len);
    os.close();
    c.close();
    try rp.finish(); // the one STATUS 2 matched, and nothing else was sent
}

test "monitor: a repeated attr id in the message is a malformed frame, never a duplicate JSON key" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var h = Hostile.init();
    defer h.deinit();
    const a = h.arena.allocator();
    try h.hello();
    try h.anyFrame();
    try h.status(1, 0, null);
    var inner: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(a, &inner, codec.ATTR.STATUS, 0);
    try codec.appendAttrU32(a, &inner, codec.ATTR.STATUS, 1);
    var ch: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(a, &ch, codec.MON.CLIENT, 1);
    try codec.appendAttrU32(a, &ch, codec.MON.PEER, 3);
    try codec.appendAttr(a, &ch, codec.MON.SEND, &.{1});
    try codec.appendAttrU32(a, &ch, codec.MON.SEQ, 1);
    try codec.appendAttrU32(a, &ch, codec.MON.TYPE, 1);
    try codec.appendAttr(a, &ch, codec.MON.DATA, inner.items);
    try h.d2c(codec.MSG.MONITOR, 2, 0, ch.items);
    // a non-UTF-8 METHOD: the whole frame is dropped and counted, not half written
    inner.clearRetainingCapacity();
    try codec.appendAttr(a, &inner, codec.ATTR.METHOD, &.{ 0xff, 0xfe, 0 });
    ch.clearRetainingCapacity();
    try codec.appendAttrU32(a, &ch, codec.MON.CLIENT, 1);
    try codec.appendAttrU32(a, &ch, codec.MON.PEER, 3);
    try codec.appendAttr(a, &ch, codec.MON.SEND, &.{1});
    try codec.appendAttrU32(a, &ch, codec.MON.SEQ, 1);
    try codec.appendAttrU32(a, &ch, codec.MON.TYPE, 5);
    try codec.appendAttr(a, &ch, codec.MON.DATA, inner.items);
    try h.d2c(codec.MSG.MONITOR, 3, 0, ch.items);
    var rp: Replay = undefined;
    try rp.init("mon-dup", h.frames.items, 1);
    rp.hang_up = true;
    defer rp.deinit();
    var c = try Client.openWith(gpa, rp.path, .{ .call_timeout_ms = 300 });
    defer c.close();
    var ms = try c.monitor();
    defer ms.close();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var closed = false;
    var tries: usize = 0;
    while (!closed and tries < 600) : (tries += 1) {
        closed = try ms.poll(&out);
        if (!closed) sleepMs(5);
    }
    try testing.expect(closed);
    try testing.expectEqual(@as(usize, 0), out.items.len);
    try testing.expectEqual(@as(u32, 2), ms.malformed);
}

// ── delta audit (dbm, 2026-11-04): handshake filtering of the own-connection verbs ──────────

test "delta audit: subscribeObject - stragglers (other seq, other type) in the handshake are skipped; a short OBJID is BadMessage (dbm)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var h = Hostile.init();
    defer h.deinit();
    const a = h.arena.allocator();
    try h.hello();
    try h.anyFrame(); // ADD_OBJECT
    try h.status(9, 6, null); // a straggler STATUS of another request
    try h.data(1, 5);
    var ch: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 99);
    try h.d2c(codec.MSG.INVOKE, 1, 0, ch.items); // right seq, not a reply: its OBJID is none of ours
    try h.status(1, 0, null);
    try h.anyFrame(); // LOOKUP
    try h.data(2, 7);
    try h.dataPath(9, "obj", 99); // a straggler entry of the right name, another seq
    try h.status(2, 0, null);
    // SUBSCRIBE{OBJID = ours (5), TARGET = theirs (7)}, byte for byte
    ch.clearRetainingCapacity();
    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 5);
    try codec.appendAttrU32(a, &ch, codec.ATTR.TARGET, 7);
    try h.rawHex(.c2d, try codec.encodeMessage(a, codec.MSG.SUBSCRIBE, 3, 0, ch.items));
    try h.status(3, 0, null);
    var rp: Replay = undefined;
    try rp.init("dbm-sub-stragglers", h.frames.items, 1);
    rp.hang_up = true;
    defer rp.deinit();
    var c = try Client.openWith(gpa, rp.path, .{ .call_timeout_ms = 300 });
    defer c.close();
    var os = try c.subscribeObject("obj");
    try testing.expectEqual(@as(u32, 5), os.own_id);
    try testing.expectEqual(@as(u32, 7), os.target_id);
    os.close();
    try rp.finish();

    // an OBJID attr too short to hold an id is a malformed answer, not a read past it
    var h2 = Hostile.init();
    defer h2.deinit();
    try h2.hello();
    try h2.anyFrame();
    var ch2: std.ArrayList(u8) = .empty;
    try codec.appendAttr(h2.arena.allocator(), &ch2, codec.ATTR.OBJID, &.{ 0, 5 });
    try h2.d2c(codec.MSG.DATA, 1, 0, ch2.items);
    try h2.status(1, 0, null);
    try testing.expectError(Error.BadMessage, hostileSubObj(&h2, "dbm-sub-short"));
}

fn registerFrame(a: std.mem.Allocator, my_id: u32, pat: []const u8, seq: u16) ![]u8 {
    var regargs: std.ArrayList(u8) = .empty;
    try codec.appendU32(a, &regargs, "object", my_id);
    try codec.appendString(a, &regargs, "pattern", pat);
    var inv: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(a, &inv, codec.ATTR.OBJID, codec.SYS_OBJECT_EVENT);
    try codec.appendAttrString(a, &inv, codec.ATTR.METHOD, "register");
    try codec.appendAttr(a, &inv, codec.ATTR.DATA, regargs.items);
    return codec.encodeMessage(a, codec.MSG.INVOKE, seq, codec.SYS_OBJECT_EVENT, inv.items);
}

/// Play `h` to `Client.subscribeMany(patterns)` (or `subscribe("")` when `empty_subscribe`); on success the
/// whole script must have been played with every client frame byte-identical.
fn hostileSubMany(h: *Hostile, tag: []const u8, patterns: []const []const u8, empty_subscribe: bool) anyerror!void {
    var rp: Replay = undefined;
    try rp.init(tag, h.frames.items, 1);
    rp.hang_up = true;
    defer rp.deinit();
    var c = try Client.openWith(testing.allocator, rp.path, .{ .call_timeout_ms = 300 });
    defer c.close();
    const r = if (empty_subscribe) c.subscribe("") else c.subscribeMany(patterns);
    last_status_seen = c.last_status;
    if (r) |st| {
        var s = st;
        s.close();
        try rp.finish();
    } else |e| return e;
}

test "delta audit: subscribeMany - every step of the handshake is a verdict; stray frames are skipped; \"\" and no pattern register \"*\" once (dbm)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const T = struct { name: []const u8, expect: ?Error, status: i32 = 0 };
    inline for ([_]T{
        .{ .name = "refused", .expect = Error.UbusError, .status = 6 },
        .{ .name = "no-objid", .expect = Error.BadMessage },
        .{ .name = "short-objid", .expect = Error.BadMessage },
        .{ .name = "stray-before-answer", .expect = null },
        .{ .name = "empty-list", .expect = null },
        .{ .name = "empty-subscribe", .expect = null },
        .{ .name = "register-refused", .expect = Error.UbusError, .status = 6 },
        .{ .name = "stragglers", .expect = null },
    }) |t| {
        var h = Hostile.init();
        defer h.deinit();
        const a = h.arena.allocator();
        try h.hello();
        try h.anyFrame(); // ADD_OBJECT
        if (comptime std.mem.eql(u8, t.name, "refused")) {
            try h.status(1, 6, null);
        } else if (comptime std.mem.eql(u8, t.name, "no-objid")) {
            try h.status(1, 0, null);
        } else if (comptime std.mem.eql(u8, t.name, "short-objid")) {
            var ch: std.ArrayList(u8) = .empty;
            try codec.appendAttr(a, &ch, codec.ATTR.OBJID, &.{ 0, 5 });
            try h.d2c(codec.MSG.DATA, 1, 0, ch.items);
            try h.status(1, 0, null);
        } else {
            const stragglers = comptime std.mem.eql(u8, t.name, "stragglers");
            if (stragglers) try h.status(9, 6, null); // another request's refusal
            try h.data(1, 5);
            if (stragglers) {
                var sc: std.ArrayList(u8) = .empty;
                try codec.appendAttrU32(a, &sc, codec.ATTR.OBJID, 99);
                try h.d2c(codec.MSG.INVOKE, 1, 0, sc.items); // right seq, not a reply
            }
            try h.status(1, 0, null);
            try h.rawHex(.c2d, try registerFrame(a, 5, "*", 2));
            if (stragglers) try h.status(9, 6, null);
            if (comptime std.mem.eql(u8, t.name, "register-refused")) {
                try h.status(2, 6, null);
            } else {
                if (comptime std.mem.eql(u8, t.name, "stray-before-answer")) {
                    var ch: std.ArrayList(u8) = .empty;
                    try codec.appendAttrU32(a, &ch, codec.ATTR.OBJID, 5);
                    try h.d2c(codec.MSG.INVOKE, 2, 0, ch.items); // not a STATUS: not the answer
                }
                try h.status(2, 0, null);
            }
        }
        const pats: []const []const u8 = if (comptime std.mem.eql(u8, t.name, "empty-list")) &.{} else &.{"*"};
        const r = hostileSubMany(&h, t.name, pats, comptime std.mem.eql(u8, t.name, "empty-subscribe"));
        if (t.expect) |e| {
            testing.expectError(e, r) catch |err| {
                std.debug.print("hostile subscribeMany case {s}\n", .{t.name});
                return err;
            };
            try testing.expectEqual(t.status, last_status_seen);
        } else {
            r catch |err| {
                std.debug.print("hostile subscribeMany case {s}: {t}\n", .{ t.name, err });
                return err;
            };
        }
    }
    // a limit of 64 patterns: the 65th is refused before any connection
    var c: Client = .{ .gpa = testing.allocator, .fd = -1, .client_id = 1 };
    var many: [65][]const u8 = @splat("a");
    try testing.expectError(Error.Unsupported, c.subscribeMany(&many));
}

test "delta audit: monitor - a straggler STATUS (other seq, other type) is not the verdict; a non-MONITOR frame is no tap line (dbm)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var h = Hostile.init();
    defer h.deinit();
    const a = h.arena.allocator();
    try h.hello();
    try h.anyFrame();
    try h.status(9, 6, null); // another seq
    var ch: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(a, &ch, codec.ATTR.STATUS, 6);
    try h.d2c(codec.MSG.DATA, 1, 0, ch.items); // right seq, not a STATUS
    try h.status(1, 0, null); // the verdict
    ch.clearRetainingCapacity();
    try ch.appendSlice(a, &.{ 0x04, 0, 0, 0x7f, 1, 2, 3, 4 });
    try h.d2c(codec.MSG.INVOKE, 3, 0, ch.items); // after the verdict: none of the tap's business
    var rp: Replay = undefined;
    try rp.init("dbm-mon-stragglers", h.frames.items, 1);
    rp.hang_up = true;
    defer rp.deinit();
    var c = try Client.openWith(gpa, rp.path, .{ .call_timeout_ms = 300 });
    defer c.close();
    var ms = try c.monitor();
    defer ms.close();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var closed = false;
    var tries: usize = 0;
    while (!closed and tries < 600) : (tries += 1) {
        closed = try ms.poll(&out);
        if (!closed) sleepMs(5);
    }
    try testing.expect(closed);
    try testing.expectEqual(@as(usize, 0), out.items.len);
    try testing.expectEqual(@as(u32, 0), ms.malformed);
    try testing.expectEqual(@as(i32, 0), c.last_status);
}
