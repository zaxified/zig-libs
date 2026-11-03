// SPDX-License-Identifier: MIT

//! Scripted-peer fuzz harness for the client's reply state machines (round 2,
//! 2026-11-03): `list`, `invoke`/`invokeReply`, `sendEvent`, `waitFor`,
//! `subscribe` and `EventStream.poll` are driven over a socketpair (a unix
//! listener for `subscribe`, which opens its own connection) by a PRNG-written
//! peer script: random frame types and sequence numbers, STATUS codes (0, 4, 6,
//! arbitrary, or an attr too short to hold one), missing or short OBJID,
//! duplicate and garbage attrs, valid and random DATA, a header whose length is
//! corrupted to a limit, and the whole byte stream cut at a random point.
//!
//! Properties, every seed: no panic, no leak (the driver's allocator checks),
//! no call outlasts its deadline (asserted with a margin), a success returns
//! valid JSON, a stream that errors or closes stays closed (`broken`, `poll`
//! `true` from then on). Reach labels (one per API and per outcome) are
//! asserted in the every-run test below, silent on success.
//!
//! `BLOBMSG_FUZZ=<runs>[,<first seed>]`, harness name `client` (see
//! `fuzz_test.zig`); run the test binary directly in ReleaseSafe.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const blobmsg = @import("root.zig");
const codec = blobmsg.codec;
const testing = std.testing;

pub const Label = enum {
    api_list,
    api_invoke,
    api_send,
    api_wait,
    api_poll,
    api_subscribe,
    ok,
    err_notfound,
    err_ubus,
    err_bad,
    err_timeout,
    err_short,
    err_toolarge,
    err_unsupported,
    poll_true,
    poll_false,
    poll_events,
};
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(l: Label) void {
    reach[@backingInt(l)] += 1;
    switch (l) {
        inline else => |c| fuzz_driver.hit(@tagName(c)),
    }
}

fn resetReach() void {
    reach = @splat(0);
}

fn expectAllReached() !void {
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn markErr(e: anyerror) void {
    switch (e) {
        error.NotFound => mark(.err_notfound),
        error.UbusError => mark(.err_ubus),
        error.BadMessage => mark(.err_bad),
        error.Timeout => mark(.err_timeout),
        error.ShortRead, error.ShortWrite, error.Connect => mark(.err_short),
        error.TooLarge => mark(.err_toolarge),
        error.Unsupported => mark(.err_unsupported),
        else => {},
    }
}

fn pick(comptime S: type, src: *S, comptime T: type, comptime options: []const T) T {
    return options[src.index(options.len)];
}

/// One scripted attr, the way a (mis)behaving daemon might send it.
fn genAttr(comptime S: type, src: *S, gpa: std.mem.Allocator, ch: *std.ArrayList(u8), id: u32) !void {
    switch (src.index(4)) {
        0 => try codec.appendAttrU32(gpa, ch, id, pick(S, src, u32, &.{ 0, 4, 6, 7, 0xffff_ffff, 1 })),
        1 => try codec.appendAttr(gpa, ch, id, &.{ 0, 1 }), // too short for a u32
        2 => {
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(gpa);
            try codec.appendInt32(gpa, &body, "n", src.valueRangeAtMost(i32, -3, 3));
            try codec.appendAttr(gpa, ch, id, body.items);
        },
        else => {
            var raw: [12]u8 = undefined;
            src.bytes(&raw);
            try codec.appendAttr(gpa, ch, id, raw[0..src.index(raw.len + 1)]);
        },
    }
}

fn put(gpa: std.mem.Allocator, out: *std.ArrayList(u8), mtype: u8, seq: u16, attrs: []const u8) !void {
    const fr = try codec.encodeMessage(gpa, mtype, seq, 0, attrs);
    defer gpa.free(fr);
    try out.appendSlice(gpa, fr);
}

fn putStatus(gpa: std.mem.Allocator, out: *std.ArrayList(u8), seq: u16, code: u32, objid: ?u32) !void {
    var ch: std.ArrayList(u8) = .empty;
    defer ch.deinit(gpa);
    try codec.appendAttrU32(gpa, &ch, codec.ATTR.STATUS, code);
    if (objid) |o| try codec.appendAttrU32(gpa, &ch, codec.ATTR.OBJID, o);
    try put(gpa, out, codec.MSG.STATUS, seq, ch.items);
}

fn putFound(gpa: std.mem.Allocator, out: *std.ArrayList(u8), seq: u16, name: []const u8, id: u32) !void {
    var ch: std.ArrayList(u8) = .empty;
    defer ch.deinit(gpa);
    try codec.appendAttrU32(gpa, &ch, codec.ATTR.OBJID, id);
    try codec.appendAttrString(gpa, &ch, codec.ATTR.OBJPATH, name);
    try put(gpa, out, codec.MSG.DATA, seq, ch.items);
    try putStatus(gpa, out, seq, 0, null);
}

fn putEvent(gpa: std.mem.Allocator, out: *std.ArrayList(u8), n: i32) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try codec.appendInt32(gpa, &body, "n", n);
    var ch: std.ArrayList(u8) = .empty;
    defer ch.deinit(gpa);
    try codec.appendAttrString(gpa, &ch, codec.ATTR.METHOD, "ev");
    try codec.appendAttr(gpa, &ch, codec.ATTR.DATA, body.items);
    try put(gpa, out, codec.MSG.INVOKE, 9, ch.items);
}

/// A coherent conversation for `api`, so the success paths are reached and the
/// damage below lands on a stream that gets past its first stop.
fn genGood(comptime S: type, src: *S, gpa: std.mem.Allocator, out: *std.ArrayList(u8), api: usize) !void {
    const code = pick(S, src, u32, &.{ 0, 0, 6 });
    switch (api) {
        0 => {
            for (0..src.index(3)) |i| try putFound(gpa, out, 1, "obj", @intCast(0x10 + i));
            try putStatus(gpa, out, 1, pick(S, src, u32, &.{ 0, 0, 4 }), null);
        },
        1, 6 => {
            if (src.index(4) == 0) return putStatus(gpa, out, 1, 4, null); // no such object
            try putFound(gpa, out, 1, "obj", 0x10);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(gpa);
            try codec.appendString(gpa, &body, "k", "v");
            var ch: std.ArrayList(u8) = .empty;
            defer ch.deinit(gpa);
            try codec.appendAttr(gpa, &ch, codec.ATTR.DATA, body.items);
            if (src.index(2) == 0) try put(gpa, out, codec.MSG.DATA, 2, ch.items);
            try putStatus(gpa, out, 2, code, 0x10);
        },
        2 => try putStatus(gpa, out, 1, code, null),
        3 => {
            try putFound(gpa, out, 1, "x", 0x10);
            try putFound(gpa, out, 2, "y", 0x11);
        },
        else => {
            if (api == 5) {
                try putStatus(gpa, out, 1, 0, 0x77);
                try putStatus(gpa, out, 2, 0, null);
            }
            for (0..src.index(4)) |i| try putEvent(gpa, out, @intCast(i));
        },
    }
}

/// The peer's bytes: `events` = INVOKE event frames (what `poll` reads),
/// otherwise replies of every type to a request whose seq is 1..3.
fn genScript(comptime S: type, src: *S, gpa: std.mem.Allocator, out: *std.ArrayList(u8), api: usize) !void {
    const events = api == 4 or api == 5;
    if (src.index(2) == 0) {
        try genGood(S, src, gpa, out, api);
        if (src.index(5) != 0) return; // mostly left intact, sometimes damaged below
    }
    const frames = src.valueRangeAtMost(u8, 0, 5);
    for (0..frames) |_| {
        var ch: std.ArrayList(u8) = .empty;
        defer ch.deinit(gpa);
        const attr_ids = [_]u32{ codec.ATTR.STATUS, codec.ATTR.OBJID, codec.ATTR.OBJPATH, codec.ATTR.DATA, codec.ATTR.SIGNATURE, codec.ATTR.METHOD, 99 };
        if (events) {
            try codec.appendAttrString(gpa, &ch, codec.ATTR.METHOD, "ev");
            try genAttr(S, src, gpa, &ch, codec.ATTR.DATA);
        } else {
            for (attr_ids) |id| if (src.index(3) == 0) try genAttr(S, src, gpa, &ch, id);
        }
        const mtype: u8 = if (events) codec.MSG.INVOKE else pick(S, src, u8, &.{ codec.MSG.STATUS, codec.MSG.STATUS, codec.MSG.DATA, codec.MSG.DATA, codec.MSG.INVOKE, 77 });
        const seq: u16 = if (src.index(8) == 0) src.value(u16) else src.valueRangeAtMost(u16, 1, 3);
        const fr = try codec.encodeMessage(gpa, mtype, seq, 0, ch.items);
        defer gpa.free(fr);
        const start = out.items.len;
        try out.appendSlice(gpa, fr);
        if (src.index(16) == 0) { // a length at a limit
            const lim = pick(S, src, u32, &.{ 0, 3, 4, 0x00ff_ffff, 1 << 20, (1 << 20) + 1, 0x8000_0000 });
            std.mem.writeInt(u32, out.items[start + codec.msghdr_len ..][0..4], lim, .big);
        }
    }
    if (src.index(6) == 0 and out.items.len > 0) out.shrinkRetainingCapacity(src.index(out.items.len));
}

fn writeAll(fd: i32, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (linux.errno(rc) != .SUCCESS) return;
        off += rc;
    }
}

fn expectJson(gpa: std.mem.Allocator, text: []const u8) !void {
    var p = std.json.parseFromSlice(std.json.Value, gpa, text, .{}) catch return error.SuccessWasNotJson;
    p.deinit();
}

const margin_ns = 1500 * std.time.ns_per_ms; // a call has 20-200 ms; this is "hung"

const SubPeer = struct {
    lfd: i32,
    script: []const u8,

    fn run(p: *SubPeer) void {
        const gpa = std.heap.page_allocator; // global-alloc-ok: fuzz peer thread body, test-only
        var fds: [2]i32 = .{ -1, -1 };
        for (0..2) |i| {
            const rc = linux.accept(p.lfd, null, null);
            if (linux.errno(rc) != .SUCCESS) break;
            fds[i] = @intCast(rc);
            const hello = codec.encodeMessage(gpa, codec.MSG.HELLO, 0, 9, &.{}) catch break;
            defer gpa.free(hello);
            writeAll(fds[i], hello);
            if (i == 1) writeAll(fds[i], p.script);
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 250 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        for (fds) |f| if (f >= 0) {
            _ = linux.close(f);
        };
    }
};

var path_counter: std.atomic.Value(u32) = .init(0);

fn pollLoop(ev: *blobmsg.EventStream, gpa: std.mem.Allocator) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    for (0..6) |_| {
        const r = ev.poll(&out) catch |e| {
            markErr(e);
            if (!ev.broken) return error.ErrorWithoutBroken;
            if (!(try ev.poll(&out))) return error.BrokenStreamNotClosed;
            return;
        };
        if (r) {
            mark(.poll_true);
            if (!ev.broken) return error.ClosedWithoutBroken;
            return;
        }
        mark(.poll_false);
    }
    if (out.items.len > 0) {
        mark(.poll_events);
        var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, out.items, "\n"), '\n');
        while (lines.next()) |l| try expectJson(gpa, l);
    }
}

fn clientHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    if (builtin.os.tag != .linux) return;
    const api = src.index(7);
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try genScript(S, src, gpa, &script, api);
    const max_reply = pick(S, src, usize, &.{ 64, 600, 1 << 20 });
    const opts: blobmsg.Options = .{ .call_timeout_ms = 20, .max_reply_bytes = max_reply };
    const t0 = nowNs();
    defer std.debug.assert(nowNs() - t0 < margin_ns + 300 * std.time.ns_per_ms);

    if (api == 5) { // subscribe: its own connection, so a unix listener
        mark(.api_subscribe);
        const lrc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(lrc) != .SUCCESS) return;
        const lfd: i32 = @intCast(lrc);
        defer _ = linux.close(lfd);
        var pb: [96]u8 = undefined;
        const path = std.fmt.bufPrintSentinel(&pb, "/tmp/zl-blobmsg-fz-{d}-{d}.sock", .{ linux.getpid(), path_counter.fetchAdd(1, .monotonic) }, 0) catch return;
        _ = linux.unlink(path.ptr);
        defer _ = linux.unlink(path.ptr);
        var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
        @memcpy(addr.path[0..path.len], path);
        const alen: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + 1);
        if (linux.errno(linux.bind(lfd, @ptrCast(&addr), alen)) != .SUCCESS) return;
        if (linux.errno(linux.listen(lfd, 2)) != .SUCCESS) return;
        var peer: SubPeer = .{ .lfd = lfd, .script = script.items };
        const th = std.Thread.spawn(.{}, SubPeer.run, .{&peer}) catch return;
        defer th.join();
        var c = blobmsg.Client.openWith(gpa, path, .{ .call_timeout_ms = 200, .max_reply_bytes = max_reply }) catch |e| {
            markErr(e);
            return;
        };
        defer c.close();
        if (c.subscribe(null)) |es_val| {
            var es = es_val;
            defer es.close();
            mark(.ok);
            try pollLoop(&es, gpa);
        } else |e| markErr(e);
        return;
    }

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return;
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    writeAll(fds[1], script.items);
    if (src.index(2) == 0) _ = linux.shutdown(fds[1], linux.SHUT.WR); // the daemon hangs up after its script

    if (api == 4) {
        mark(.api_poll);
        var ev: blobmsg.EventStream = .{ .gpa = gpa, .fd = fds[0], .opts = opts };
        try pollLoop(&ev, gpa);
        return;
    }

    var c: blobmsg.Client = .{ .gpa = gpa, .fd = fds[0], .client_id = 1, .opts = opts };
    switch (api) {
        0 => {
            mark(.api_list);
            const pat: ?[]const u8 = pick(S, src, ?[]const u8, &.{ null, "a*", "obj" });
            if (c.list(pat)) |objs| {
                defer blobmsg.freeObjects(gpa, objs);
                mark(.ok);
                for (objs) |o| if (o.signature_json) |j| try expectJson(gpa, j);
            } else |e| markErr(e);
        },
        1, 6 => {
            mark(.api_invoke);
            const args: ?[]const u8 = pick(S, src, ?[]const u8, &.{ null, "{\"a\":1}" });
            if (api == 1) {
                if (c.invoke("obj", "m", args)) |d| {
                    defer gpa.free(d);
                    mark(.ok);
                    try expectJson(gpa, d);
                } else |e| markErr(e);
            } else if (c.invokeReply("obj", "m", args)) |r| {
                defer gpa.free(r.data);
                mark(.ok);
                try expectJson(gpa, r.data);
            } else |e| markErr(e);
        },
        2 => {
            mark(.api_send);
            const ty = pick(S, src, []const u8, &.{ "t.x", "t.x", "" });
            if (c.sendEvent(ty, "{\"n\":1}")) {
                mark(.ok);
            } else |e| markErr(e);
        },
        else => {
            mark(.api_wait);
            if (c.waitFor(&.{ "x", "y" }, 40)) {
                mark(.ok);
            } else |e| markErr(e);
        },
    }
    // A request that failed mid-stream leaves the client broken, never half-alive:
    // a later call answers from state without touching the socket.
    if (c.broken) try testing.expectError(error.ShortRead, c.list(null));
}

test "client fuzz driver: BLOBMSG_FUZZ (client)" {
    try fuzz_driver.runAll(.{
        .{ clientHarness, .{ .prefix = "BLOBMSG_FUZZ", .name = "client" } },
    });
}

test "client fuzz harness: 300 seeds in every test run, no call outlasts its deadline, and every API and outcome is reached" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    resetReach();
    for (0..300) |sd| {
        var prng = std.Random.DefaultPrng.init(sd);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        clientHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("blobmsg client seed {d}: {t}\n", .{ sd, err });
            return err;
        };
    }
    try expectAllReached();
}
