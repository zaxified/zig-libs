// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GY), findings BM-1 .. BM-5; see
//! ~/CML/20261029-panic-sweep/blobmsg-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const blobmsg = @import("root.zig");
const codec = blobmsg.codec;

// ── forked child helper (stderr captured; exit code reported) ───────────────

const Child = struct { died: bool, code: u32, len: usize };

fn runChild(comptime body: fn () u8, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        linux.exit_group(body());
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 10_000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{
        .died = linux.W.IFSIGNALED(status),
        .code = linux.W.EXITSTATUS(status),
        .len = if (linux.errno(n) == .SUCCESS) n else 0,
    };
}

// Needles live in consts, never inline in the call (GS trap).
const needle_id = "blobmsg: idLen: attr id above 127";
const needle_len = "blobmsg: idLen: attr length above 16 MiB - 1";

fn expectPanicMessage(comptime body: fn () u8, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

// ── BM-1: iterators are terminal after their first error ────────────────────

test "AttrIterator is terminal after an error, so `catch continue` cannot spin (sweep BM-1)" {
    // Declared length runs past the buffer; `off` never moves on error.
    var it: codec.AttrIterator = .{ .buf = &.{ 0x83, 0x00, 0x00, 0x20, 0xaa } };
    var calls: usize = 0;
    var errors: usize = 0;
    while (calls < 1000) : (calls += 1) {
        const a = it.next() catch {
            errors += 1;
            continue;
        };
        if (a == null) break;
    }
    try testing.expect(calls < 1000);
    try testing.expectEqual(@as(usize, 1), errors);

    // Header cut short, and an impossibly small length: same.
    it = .{ .buf = &.{ 0x83, 0x00 } };
    try testing.expectError(error.Truncated, it.next());
    try testing.expectEqual(@as(?codec.Attr, null), try it.next());
    it = .{ .buf = &.{ 0x83, 0x00, 0x00, 0x02 } };
    try testing.expectError(error.BadLength, it.next());
    try testing.expectEqual(@as(?codec.Attr, null), try it.next());
}

test "FieldIterator: a framing error is terminal; a bad field is skipped, both bounded (sweep BM-1)" {
    var f = codec.FieldIterator.init(&.{ 0x85, 0x00, 0x00, 0x40 });
    var calls: usize = 0;
    var errors: usize = 0;
    while (calls < 1000) : (calls += 1) {
        const x = f.next() catch {
            errors += 1;
            continue;
        };
        if (x == null) break;
    }
    try testing.expect(calls < 1000);
    try testing.expectEqual(@as(usize, 1), errors);

    // A well-framed field with a bad header (INT64 in a 2-byte payload) errors
    // once and the walk moves on to the next attr.
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try codec.appendField(gpa, &buf, codec.BM.INT64, "x", &.{ 1, 2 });
    try codec.appendInt32(gpa, &buf, "y", 7);
    var g = codec.FieldIterator.init(buf.items);
    try testing.expectError(error.BadLength, g.next());
    try testing.expectEqual(@as(i32, 7), (try g.next()).?.value.int32);
    try testing.expectEqual(@as(?codec.Field, null), try g.next());
}

test "hostile shapes: deep nesting, name past the attr, typed value in a short attr" {
    const gpa = testing.allocator;
    // 2000 nested tables: the JSON decoder stops at max_depth instead of recursing.
    var cur: std.ArrayList(u8) = .empty;
    defer cur.deinit(gpa);
    var d: usize = 0;
    while (d < 2000) : (d += 1) {
        var next: std.ArrayList(u8) = .empty;
        errdefer next.deinit(gpa);
        try codec.appendTable(gpa, &next, "t", cur.items);
        cur.deinit(gpa);
        cur = next;
    }
    try testing.expectError(error.TooDeep, codec.decodeToJsonAlloc(gpa, cur.items));
    // namelen 0xffff in a 10-byte attr.
    var f = codec.FieldIterator.init(&.{ 0x85, 0x00, 0x00, 0x0a, 0xff, 0xff, 'a', 0, 0, 0, 0, 0 });
    try testing.expectError(error.Truncated, f.next());
    // INT64 from a 2-byte payload.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try codec.appendField(gpa, &buf, codec.BM.INT64, "", &.{ 1, 2 });
    f = codec.FieldIterator.init(buf.items);
    try testing.expectError(error.BadLength, f.next());
}

// ── BM-4: idLen caller contract is a checked panic ──────────────────────────

fn idHuge() u8 {
    _ = codec.idLen(200, false, 8);
    return 0;
}
fn lenHuge() u8 {
    _ = codec.idLen(1, false, codec.LEN_MASK + 1);
    return 0;
}
fn appendAttrHugeId() u8 {
    var out: std.ArrayList(u8) = .empty;
    codec.appendAttr(std.heap.page_allocator, &out, 128, "x") catch return 0; // global-alloc-ok: test child
    return 0;
}

test "idLen / appendAttr: an id above 127 or a length above 24 bits is a checked panic (sweep BM-4)" {
    try testing.expectEqual(@as(u32, 0x7f000008), codec.idLen(127, false, 8));
    try expectPanicMessage(idHuge, needle_id);
    try expectPanicMessage(lenHuge, needle_len);
    try expectPanicMessage(appendAttrHugeId, needle_id);
}

test "alignUp is total near maxInt (sweep BM-5)" {
    try testing.expectEqual(@as(usize, std.math.maxInt(usize) - 3), codec.alignUp(std.math.maxInt(usize)));
    try testing.expectEqual(@as(usize, 8), codec.alignUp(5));
}

// ── BM-2: a vanished peer is ShortWrite, never SIGPIPE ──────────────────────

fn sigpipeChild() u8 {
    const act: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.DFL },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.PIPE, &act, null);
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return 2;
    _ = linux.close(fds[1]); // the daemon went away
    var c: blobmsg.Client = .{ .gpa = std.heap.page_allocator, .fd = fds[0], .client_id = 1 }; // global-alloc-ok: test child
    if (c.list(null)) |objs| {
        blobmsg.freeObjects(std.heap.page_allocator, objs); // global-alloc-ok: test child
        return 3;
    } else |e| {
        if (e != error.ShortWrite) return 4;
        if (!c.broken) return 5; // RV-BM-2: the failed write must poison the client
        if (c.list(null)) |_| return 6 else |e2| return if (e2 == error.ShortRead) 0 else 7;
    }
}

test "Client.list to a vanished daemon returns ShortWrite and survives default SIGPIPE (sweep BM-2)" {
    var buf: [256]u8 = undefined;
    const c = try runChild(sigpipeChild, &buf);
    try testing.expect(!c.died);
    try testing.expectEqual(@as(u32, 0), c.code);
}

// ── BM-3: the call deadline also bounds a stalled frame ─────────────────────

const StallCtx = struct { fd: i32 };

fn stallDaemon(ctx: *StallCtx) void {
    var req: [256]u8 = undefined;
    _ = linux.read(ctx.fd, &req, req.len); // the LOOKUP request
    // msghdr (DATA, seq 1) + a top attr declaring 1000 bytes, then nothing.
    const hdr = [_]u8{ 0, codec.MSG.DATA, 0, 1, 0, 0, 0, 0, 0, 0, 0x03, 0xe8 };
    _ = linux.write(ctx.fd, &hdr, hdr.len);
    _ = linux.read(ctx.fd, &req, req.len); // blocks until the client closes
}

test "Client.list: a daemon that stalls inside a frame ends in Timeout, not a hang (sweep BM-3)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return error.SkipZigTest;
    // Safety net only: without the in-frame deadline the recv would end in
    // ShortRead after this 6 s socket timeout (test fails on the error
    // identity); with it the 2 s call deadline answers first with Timeout.
    const tv = linux.timeval{ .sec = 6, .usec = 0 };
    _ = linux.setsockopt(fds[0], linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    var ctx: StallCtx = .{ .fd = fds[1] };
    const th = try std.Thread.spawn(.{}, stallDaemon, .{&ctx});
    var c: blobmsg.Client = .{ .gpa = testing.allocator, .fd = fds[0], .client_id = 1 };
    c.seq = 0;
    const r = c.list(null);
    _ = linux.close(fds[0]);
    th.join();
    _ = linux.close(fds[1]);
    try testing.expectError(error.Timeout, r);
    // Mid-frame stall: the stream is desynchronised, so the client is poisoned
    // and answers from state (the fd is already closed here) -- sweep RV-BM-2.
    try testing.expect(c.broken);
    try testing.expectError(error.ShortRead, c.list(null));
    try testing.expectError(error.ShortRead, c.invoke("system", "board", null));
}

// ── RV-BM-1 / RV-BM-2: EventStream.poll ─────────────────────────────────────

fn eventFrame(gpa: std.mem.Allocator, method: []const u8, data: []const u8) ![]u8 {
    var children: std.ArrayList(u8) = .empty;
    defer children.deinit(gpa);
    try codec.appendAttrString(gpa, &children, codec.ATTR.METHOD, method);
    try codec.appendAttr(gpa, &children, codec.ATTR.DATA, data);
    return codec.encodeMessage(gpa, codec.MSG.INVOKE, 0, 0, children.items);
}

fn writeFd(fd: i32, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (linux.errno(rc) != .SUCCESS) return;
        off += rc;
    }
}

const Flood = struct { fd: i32, frames: []const []const u8 };

fn floodThread(f: *Flood) void {
    for (f.frames) |fr| writeFd(f.fd, fr);
    _ = linux.close(f.fd); // EOF after the last frame
}

fn countLines(s: []const u8) usize {
    return std.mem.count(u8, s, "\n");
}

test "EventStream.poll: a drain stopped by the byte budget is `false`, loses no event, and EOF is `true` (sweep RV-BM-1)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return error.SkipZigTest;

    // 5 events of ~300 KB: the 1 MiB drain budget fits 3, the 4th must stay unread.
    const big = try gpa.alloc(u8, 300_000);
    defer gpa.free(big);
    @memset(big, 'x');
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(gpa);
    try codec.appendString(gpa, &data, "v", big);
    var frames: [5][]u8 = undefined;
    var made: usize = 0;
    defer for (frames[0..made]) |f| gpa.free(f);
    for (&frames, 0..) |*f, i| {
        var name: [8]u8 = undefined;
        f.* = try eventFrame(gpa, try std.fmt.bufPrint(&name, "e{d}", .{i}), data.items);
        made += 1;
    }
    var flood: Flood = .{ .fd = fds[1], .frames = @ptrCast(&frames) };
    const th = try std.Thread.spawn(.{}, floodThread, .{&flood});

    var ev: blobmsg.EventStream = .{ .gpa = gpa, .fd = fds[0] };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var stopped_by_budget = false;
    var tries: usize = 0;
    var closed = false;
    while (tries < 5000) : (tries += 1) {
        const before = countLines(out.items);
        closed = try ev.poll(&out);
        if (closed) break;
        if (countLines(out.items) - before == 3) stopped_by_budget = true;
        const ts: linux.timespec = .{ .sec = 0, .nsec = 2 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
    }
    _ = linux.close(fds[0]); // also unblocks the writer if the stream ended early
    th.join();
    try testing.expect(closed);
    // `true` only after every event was delivered, in order, none dropped.
    try testing.expectEqual(@as(usize, 5), countLines(out.items));
    var it = std.mem.splitScalar(u8, out.items, '\n');
    var i: usize = 0;
    while (it.next()) |line| {
        if (line.len == 0) continue;
        var want: [16]u8 = undefined;
        const w = try std.fmt.bufPrint(&want, "{{\"e{d}\":", .{i});
        try testing.expect(std.mem.startsWith(u8, line, w));
        i += 1;
    }
    try testing.expect(stopped_by_budget); // the budget did stop a drain after exactly 3 events
}

test "EventStream.poll: a malformed event is skipped, not an error (sweep RV-BM-1)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.close(fds[0]);
    // 1: DATA whose blobmsg field is impossible; 2: DATA whose attr walk fails; then 3 and a good one.
    const bad_field = [_]u8{ 0x85, 0x00, 0x00, 0x40 };
    const bad_walk = [_]u8{ 0x02, 0x00, 0x00, 0x20, 0xaa };
    var good: std.ArrayList(u8) = .empty;
    defer good.deinit(gpa);
    try codec.appendInt32(gpa, &good, "n", 7);
    for ([_][]const u8{ &bad_field, &bad_walk }) |d| {
        const f = try eventFrame(gpa, "ev", d);
        defer gpa.free(f);
        writeFd(fds[1], f);
    }
    // 3: a frame whose own attr walk is malformed (declared length past the payload).
    const garbage = try codec.encodeMessage(gpa, codec.MSG.INVOKE, 0, 0, &.{ 0x02, 0x00, 0x00, 0x20, 0xaa });
    defer gpa.free(garbage);
    writeFd(fds[1], garbage);
    const f = try eventFrame(gpa, "ev", good.items);
    defer gpa.free(f);
    writeFd(fds[1], f);
    _ = linux.close(fds[1]);
    var ev: blobmsg.EventStream = .{ .gpa = gpa, .fd = fds[0] };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try testing.expect(try ev.poll(&out)); // EOF reached after the three frames
    try testing.expectEqualStrings("{\"ev\":{\"n\":7}}\n", out.items);
}

fn halfFrameThread(ctx: *StallCtx) void {
    // msghdr + a top attr declaring 1000 bytes, then nothing.
    const hdr = [_]u8{ 0, codec.MSG.INVOKE, 0, 1, 0, 0, 0, 0, 0, 0, 0x03, 0xe8 };
    _ = linux.write(ctx.fd, &hdr, hdr.len);
    var b: [8]u8 = undefined;
    _ = linux.read(ctx.fd, &b, b.len); // until the client closes
}

test "EventStream.poll: a frame that stalls half-read breaks the stream, which then reports closed (sweep RV-BM-2)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return error.SkipZigTest;
    var ctx: StallCtx = .{ .fd = fds[1] };
    const th = try std.Thread.spawn(.{}, halfFrameThread, .{&ctx});
    var ev: blobmsg.EventStream = .{ .gpa = testing.allocator, .fd = fds[0] };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    // Wait until the header is readable, then poll: it blocks to the 2 s deadline.
    var pfd = [_]linux.pollfd{.{ .fd = fds[0], .events = linux.POLL.IN, .revents = 0 }};
    _ = linux.poll(&pfd, 1, 2000);
    try testing.expect(try ev.poll(&out));
    try testing.expect(ev.broken);
    _ = linux.close(fds[0]);
    th.join();
    _ = linux.close(fds[1]);
    // Closed fd: answered from state, the socket is not touched.
    try testing.expect(try ev.poll(&out));
    try testing.expectEqual(@as(usize, 0), out.items.len);
}

test "a broken Client / EventStream answers from state without touching the socket (sweep RV-BM-2)" {
    var c: blobmsg.Client = .{ .gpa = testing.allocator, .fd = -1, .client_id = 1, .broken = true };
    try testing.expectError(error.ShortRead, c.list(null));
    try testing.expectError(error.ShortRead, c.invoke("a", "b", null));
    var ev: blobmsg.EventStream = .{ .gpa = testing.allocator, .fd = -1, .broken = true };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try testing.expect(try ev.poll(&out));
}
