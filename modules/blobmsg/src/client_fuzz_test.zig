// SPDX-License-Identifier: MIT

//! Scripted-peer fuzz harness for the client's reply state machines (rounds 2
//! and 3, 2026-11-03): `list`, `invoke`/`invokeReply`, `sendEvent`, `waitFor`,
//! `subscribe` and `EventStream.poll`, driven over a socketpair (a unix
//! listener for `subscribe`, which opens its own connection) by a PRNG-written
//! peer script. Half the scripts are a coherent conversation whose frames are
//! then damaged IN PLACE (a STATUS attr dropped, cut to 2 bytes, another code,
//! another seq, an OBJID dropped or cut), so the client reads the damage before
//! it returns; the rest are random frames; both can get a length corrupted to a
//! limit and the byte stream cut at a random point. The peer then hangs up
//! (`shutdown(WR)`), except in an explicit stall mode (header / body / silent,
//! 4 ms deadlines) that proves a stalled peer ends in `Timeout`.
//!
//! Properties, every seed: no panic, no leak (the driver's allocator checks), no
//! call outlasts its deadline (asserted with a margin), a success returns valid
//! JSON, a stream that errors or closes stays closed (`broken`, `poll` `true`
//! from then on), and `poll` against a stalled peer ends. Reach labels (one per
//! API and per outcome origin) are asserted in the every-run test, silent on
//! success.
//!
//! Does NOT reach: a real daemon's bytes (only the codec's captured ones feed
//! the codec harnesses), `poll`/`recv` failing with a non-EOF errno (a socket
//! cannot inject one), a frame stalled mid-body for `subscribe` (only `poll`
//! has a stall mode), ENOMEM paths (the driver's allocator does not fail).
//! Replay: a seed replays exactly for every API but `subscribe`, whose
//! listener thread can turn a slow scheduler into an extra `Connect`.
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
    ok_invoke_nonzero,
    err_notfound,
    err_ubus,
    bad_list,
    bad_invoke,
    bad_send,
    bad_wait,
    bad_sub,
    timeout_deadline,
    timeout_header,
    timeout_body,
    err_short,
    toolarge_poll,
    toolarge_read,
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
    var missing = false;
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        missing = true;
    };
    if (missing) return error.HarnessDoesNotReach;
}

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn sleepMs(ms: u64) void {
    const ts: linux.timespec = .{ .sec = 0, .nsec = @intCast(ms * std.time.ns_per_ms) };
    _ = linux.nanosleep(&ts, null);
}

const Stall = enum { none, header, body, silent };

/// Which API the seed drives (the index `harness` draws).
const Api = enum(u8) { list, invoke, send, wait, poll, subscribe, invoke_reply };

fn markErr(e: anyerror, api: Api, stall: Stall, in_poll: bool) void {
    switch (e) {
        error.NotFound => mark(.err_notfound),
        error.UbusError => mark(.err_ubus),
        error.BadMessage => switch (api) {
            .list => mark(.bad_list),
            .invoke, .invoke_reply => mark(.bad_invoke),
            .send => mark(.bad_send),
            .wait => mark(.bad_wait),
            .subscribe => mark(.bad_sub),
            .poll => {},
        },
        error.Timeout => if (in_poll and stall == .header) mark(.timeout_header) else if (in_poll and stall == .body) mark(.timeout_body) else mark(.timeout_deadline),
        error.ShortRead, error.ShortWrite, error.Connect => mark(.err_short),
        error.TooLarge => if (in_poll) mark(.toolarge_poll) else mark(.toolarge_read),
        error.Unsupported => mark(.err_unsupported),
        else => {},
    }
}

fn pick(comptime S: type, src: *S, comptime T: type, comptime options: []const T) T {
    return options[src.index(options.len)];
}

fn put(gpa: std.mem.Allocator, out: *std.ArrayList(u8), mtype: u8, seq: u16, attrs: []const u8) !void {
    const fr = try codec.encodeMessage(gpa, mtype, seq, 0, attrs);
    defer gpa.free(fr);
    try out.appendSlice(gpa, fr);
}

/// A STATUS, damaged in place 3 times in 8: the code attr dropped, cut to 2
/// bytes, another code, or another seq.
fn putStatus(comptime S: type, src: *S, gpa: std.mem.Allocator, out: *std.ArrayList(u8), seq: u16, code: u32, objid: ?u32) !void {
    return putStatusN(S, src, gpa, out, seq, code, objid, 8);
}

/// `putStatus` damaging it 4 times in `den` (>= 4).
fn putStatusN(comptime S: type, src: *S, gpa: std.mem.Allocator, out: *std.ArrayList(u8), seq: u16, code: u32, objid: ?u32, den: usize) !void {
    var c = code;
    var sq = seq;
    var drop = false;
    var short = false;
    switch (src.index(den)) {
        0 => drop = true,
        1 => short = true,
        2 => c = pick(S, src, u32, &.{ 4, 6, 7, 0xffff_ffff, 1 }),
        3 => sq = seq +% 1,
        else => {},
    }
    var ch: std.ArrayList(u8) = .empty;
    defer ch.deinit(gpa);
    if (short) try codec.appendAttr(gpa, &ch, codec.ATTR.STATUS, &.{ 0, 1 }) else if (!drop) try codec.appendAttrU32(gpa, &ch, codec.ATTR.STATUS, c);
    if (objid) |o| try codec.appendAttrU32(gpa, &ch, codec.ATTR.OBJID, o);
    try put(gpa, out, codec.MSG.STATUS, sq, ch.items);
}

/// A LOOKUP answer for `name` (an entry, then the closing STATUS), the entry's
/// OBJID dropped or cut 2 times in 8.
fn putFound(comptime S: type, src: *S, gpa: std.mem.Allocator, out: *std.ArrayList(u8), seq: u16, name: []const u8, id: u32) !void {
    var ch: std.ArrayList(u8) = .empty;
    defer ch.deinit(gpa);
    switch (src.index(8)) {
        0 => {},
        1 => try codec.appendAttr(gpa, &ch, codec.ATTR.OBJID, &.{ 0, 1 }),
        else => try codec.appendAttrU32(gpa, &ch, codec.ATTR.OBJID, id),
    }
    try codec.appendAttrString(gpa, &ch, codec.ATTR.OBJPATH, name);
    try put(gpa, out, codec.MSG.DATA, seq, ch.items);
    try putStatus(S, src, gpa, out, seq, 0, null);
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

/// A coherent conversation for `api`, every STATUS/LOOKUP frame damaged in
/// place with some probability (see `putStatus`, `putFound`).
fn genGood(comptime S: type, src: *S, gpa: std.mem.Allocator, out: *std.ArrayList(u8), api: Api) !void {
    const code = pick(S, src, u32, &.{ 0, 0, 6 });
    switch (api) {
        .list => {
            for (0..src.index(3)) |i| try putFound(S, src, gpa, out, 1, "obj", @intCast(0x10 + i));
            try putStatus(S, src, gpa, out, 1, pick(S, src, u32, &.{ 0, 0, 4 }), null);
        },
        .invoke, .invoke_reply => {
            if (src.index(4) == 0) return putStatus(S, src, gpa, out, 1, 4, null); // no such object
            try putFound(S, src, gpa, out, 1, "obj", 0x10);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(gpa);
            try codec.appendString(gpa, &body, "k", "v");
            var ch: std.ArrayList(u8) = .empty;
            defer ch.deinit(gpa);
            try codec.appendAttr(gpa, &ch, codec.ATTR.DATA, body.items);
            if (src.index(2) == 0) try put(gpa, out, codec.MSG.DATA, 2, ch.items);
            try putStatus(S, src, gpa, out, 2, code, 0x10);
        },
        .send => try putStatus(S, src, gpa, out, 1, code, null),
        .wait => {
            try putFound(S, src, gpa, out, 1, "x", 0x10);
            try putFound(S, src, gpa, out, 2, "y", 0x11);
        },
        .poll, .subscribe => {
            if (api == .subscribe) {
                try putStatusN(S, src, gpa, out, 1, 0, 0x77, 5);
                try putStatusN(S, src, gpa, out, 2, 0, null, 5);
            }
            for (0..src.index(4)) |i| try putEvent(gpa, out, @intCast(i));
        },
    }
}

/// Random frames of every type to a request whose seq is 1..3 (events: INVOKE
/// frames), a length at a limit now and then, and the stream cut at a random
/// point now and then.
fn genRandom(comptime S: type, src: *S, gpa: std.mem.Allocator, out: *std.ArrayList(u8), events: bool) !void {
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
        const start = out.items.len;
        try put(gpa, out, mtype, seq, ch.items);
        if (src.index(16) == 0) { // a length at a limit
            const lim = pick(S, src, u32, &.{ 0, 3, 4, 0x00ff_ffff, 1 << 20, (1 << 20) + 1, 0x8000_0000 });
            std.mem.writeInt(u32, out.items[start + codec.msghdr_len ..][0..4], lim, .big);
        }
    }
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

fn genScript(comptime S: type, src: *S, gpa: std.mem.Allocator, out: *std.ArrayList(u8), api: Api, stall: Stall) !void {
    const events = api == .poll or api == .subscribe;
    // A header/body stall needs its tail to stay a tail: only aligned frames
    // before it (a truncation or a corrupted length could let the tail
    // complete a frame, and then nothing is left to stall on).
    var done = stall == .header or stall == .body;
    if (done) try genGood(S, src, gpa, out, api) else if (src.index(2) == 0) {
        try genGood(S, src, gpa, out, api);
        done = src.index(5) != 0; // mostly just the (damaged) conversation
    }
    if (!done) {
        try genRandom(S, src, gpa, out, events);
        if (src.index(6) == 0 and out.items.len > 0) out.shrinkRetainingCapacity(src.index(out.items.len));
    }
    // A stall ends the script: a partial header, or a complete header and 5 of 100 body bytes.
    switch (stall) {
        .header => try out.appendSlice(gpa, &.{ 0, codec.MSG.INVOKE, 0 }),
        .body => try out.appendSlice(gpa, &.{ 0, codec.MSG.INVOKE, 0, 1, 0, 0, 0, 0, 0, 0, 0, 104, 1, 2, 3, 4, 5 }),
        else => {},
    }
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

const margin_ns = 1500 * std.time.ns_per_ms; // a call has 4-200 ms; this is "hung"

const SubPeer = struct {
    lfd: i32,
    script: []const u8,

    fn run(p: *SubPeer) void {
        const gpa = std.heap.page_allocator; // global-alloc-ok: fuzz peer thread body, test-only
        for (0..2) |i| {
            const rc = linux.accept(p.lfd, null, null);
            if (linux.errno(rc) != .SUCCESS) return; // the listener was shut down
            const fd: i32 = @intCast(rc);
            defer _ = linux.close(fd);
            const hello = codec.encodeMessage(gpa, codec.MSG.HELLO, 0, 9, &.{}) catch return;
            defer gpa.free(hello);
            writeAll(fd, hello);
            if (i == 1) {
                // The subscribe connection: the script, then a hang-up of OUR
                // write side only (the client still sends its requests), and the
                // requests are drained until the client closes.
                writeAll(fd, p.script);
                _ = linux.shutdown(fd, linux.SHUT.WR);
                var sink: [256]u8 = undefined;
                while (true) {
                    const n = linux.read(fd, &sink, sink.len);
                    if (linux.errno(n) != .SUCCESS or n == 0) break;
                }
            }
        }
    }
};

var path_counter: std.atomic.Value(u32) = .init(0);

fn pollLoop(ev: *blobmsg.EventStream, gpa: std.mem.Allocator, api: Api, stall: Stall) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const expect_end = stall == .header or stall == .body;
    const rounds: usize = if (expect_end) 400 else 6;
    var ended = false;
    for (0..rounds) |_| {
        const r = ev.poll(&out) catch |e| {
            markErr(e, api, stall, true);
            if (!ev.broken) return error.ErrorWithoutBroken;
            if (!(try ev.poll(&out))) return error.BrokenStreamNotClosed;
            ended = true;
            break;
        };
        if (r) {
            mark(.poll_true);
            if (!ev.broken) return error.ClosedWithoutBroken;
            ended = true;
            break;
        }
        mark(.poll_false);
        if (expect_end) sleepMs(1);
    }
    // A stalled peer must END the poll loop (Timeout, or an earlier hang-up/limit):
    // `false` for ever is the spin this guards.
    if (expect_end and !ended) {
        std.debug.print("PollSpins: api {t} stall {t} max_reply {d} stall_ns {d}\n", .{ api, stall, ev.opts.max_reply_bytes, ev.stall_ns });
        return error.PollSpins;
    }
    if (out.items.len > 0) {
        mark(.poll_events);
        var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, out.items, "\n"), '\n');
        while (lines.next()) |l| try expectJson(gpa, l);
    }
}

fn clientHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    if (builtin.os.tag != .linux) return;
    const api: Api = @fromBackingInt(@intCast(src.index(7)));
    var stall: Stall = if (src.index(if (api == .poll) 3 else 8) == 0) pick(S, src, Stall, &.{ .header, .body, .silent }) else .none;
    if (api == .subscribe) stall = .none;
    if (api != .poll and stall != .none) stall = .silent;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try genScript(S, src, gpa, &script, api, stall);
    const max_reply = pick(S, src, usize, &.{ 64, 600, 1 << 20 });
    const opts: blobmsg.Options = .{ .call_timeout_ms = if (stall == .none) 20 else 4, .max_reply_bytes = max_reply };
    const t0 = nowNs();
    defer std.debug.assert(nowNs() - t0 < margin_ns + 300 * std.time.ns_per_ms);

    if (api == .subscribe) { // its own connection, so a unix listener
        mark(.api_subscribe);
        const lrc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(lrc) != .SUCCESS) return;
        const lfd: i32 = @intCast(lrc);
        var th: ?std.Thread = null;
        // Unblock the peer's `accept` BEFORE joining it: a failed `openWith`
        // leaves it waiting there, and a join first would wait for ever.
        defer {
            _ = linux.shutdown(lfd, linux.SHUT.RDWR);
            if (th) |t| t.join();
            _ = linux.close(lfd);
        }
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
        th = std.Thread.spawn(.{}, SubPeer.run, .{&peer}) catch return;
        var c = blobmsg.Client.openWith(gpa, path, .{ .call_timeout_ms = 200, .max_reply_bytes = max_reply }) catch |e| {
            markErr(e, api, stall, false);
            return;
        };
        defer c.close();
        if (c.subscribe(null)) |es_val| {
            var es = es_val;
            defer es.close();
            mark(.ok);
            try pollLoop(&es, gpa, api, stall);
        } else |e| markErr(e, api, stall, false);
        return;
    }

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return;
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    writeAll(fds[1], script.items);
    if (stall == .none) _ = linux.shutdown(fds[1], linux.SHUT.WR); // the daemon hangs up after its script

    if (api == .poll) {
        mark(.api_poll);
        var ev: blobmsg.EventStream = .{ .gpa = gpa, .fd = fds[0], .opts = opts };
        try pollLoop(&ev, gpa, api, stall);
        return;
    }

    var c: blobmsg.Client = .{ .gpa = gpa, .fd = fds[0], .client_id = 1, .opts = opts };
    switch (api) {
        .list => {
            mark(.api_list);
            const pat: ?[]const u8 = pick(S, src, ?[]const u8, &.{ null, "a*", "obj" });
            if (c.list(pat)) |objs| {
                defer blobmsg.freeObjects(gpa, objs);
                mark(.ok);
                for (objs) |o| if (o.signature_json) |j| try expectJson(gpa, j);
            } else |e| markErr(e, api, stall, false);
        },
        .invoke, .invoke_reply => {
            mark(.api_invoke);
            const args: ?[]const u8 = pick(S, src, ?[]const u8, &.{ null, "{\"a\":1}" });
            if (api == .invoke) {
                if (c.invoke("obj", "m", args)) |d| {
                    defer gpa.free(d);
                    mark(.ok);
                    try expectJson(gpa, d);
                } else |e| markErr(e, api, stall, false);
            } else if (c.invokeReply("obj", "m", args)) |r| {
                defer gpa.free(r.data);
                mark(if (r.status != 0) .ok_invoke_nonzero else .ok);
                try expectJson(gpa, r.data);
            } else |e| markErr(e, api, stall, false);
        },
        .send => {
            mark(.api_send);
            const ty = pick(S, src, []const u8, &.{ "t.x", "t.x", "" });
            if (c.sendEvent(ty, "{\"n\":1}")) {
                mark(.ok);
            } else |e| markErr(e, api, stall, false);
        },
        else => {
            mark(.api_wait);
            if (c.waitFor(&.{ "x", "y" }, if (stall == .none) 40 else 10)) {
                mark(.ok);
            } else |e| markErr(e, api, stall, false);
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

test "client fuzz harness: 600 seeds in every test run, no call outlasts its deadline, and every API and outcome origin is reached" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    resetReach();
    for (0..600) |sd| {
        var prng = std.Random.DefaultPrng.init(sd);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        clientHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("blobmsg client seed {d}: {t}\n", .{ sd, err });
            return err;
        };
    }
    try expectAllReached();
}
