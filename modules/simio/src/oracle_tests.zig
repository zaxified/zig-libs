// SPDX-License-Identifier: MIT

//! The differential oracle (SPEC § Anchoring): one program, written against
//! `std.Io` only, runs on `std.Io.Threaded` over the real loopback and file
//! system and on simio with no faults, and both must report the same
//! observable results — stream and datagram payloads, file contents and
//! names after a sync and a rename, a receive that times out, an accept that
//! is canceled. A divergence is a place where simio's `std.Io` is not the
//! one real code runs on.

const std = @import("std");
const sched = @import("sched.zig");

const Io = std.Io;
const net = Io.net;
const Dir = Io.Dir;
const Sim = sched.Sim;
const testing = std.testing;

const Report = struct {
    /// Hash of every byte the client got back over the stream.
    stream: u64 = 0,
    stream_bytes: usize = 0,
    /// Hash of every datagram reply.
    dgram: u64 = 0,
    dgrams: usize = 0,
    /// What a receive on a silent socket ended with.
    silent_receive: ?anyerror = null,
    /// What a canceled accept ended with.
    canceled_accept: ?anyerror = null,
    /// Echoed over a Unix-domain stream, and over a socketpair.
    unix: [16]u8 = undefined,
    unix_len: usize = 0,
    /// The file's content after write, sync, rename and reopen.
    file: [64]u8 = undefined,
    file_len: usize = 0,
    /// Directory entries afterwards, sorted, joined by '/'.
    names: [128]u8 = undefined,
    names_len: usize = 0,
    done: bool = false,

    fn eql(a: *const Report, b: *const Report) bool {
        return a.stream == b.stream and a.stream_bytes == b.stream_bytes and
            a.dgram == b.dgram and a.dgrams == b.dgrams and
            a.silent_receive == b.silent_receive and a.canceled_accept == b.canceled_accept and
            std.mem.eql(u8, a.unix[0..a.unix_len], b.unix[0..b.unix_len]) and
            std.mem.eql(u8, a.file[0..a.file_len], b.file[0..b.file_len]) and
            std.mem.eql(u8, a.names[0..a.names_len], b.names[0..b.names_len]) and
            a.done and b.done;
    }
};

// ── the program ────────────────────────────────────────────────────────────

/// Echoes every byte back, upper-cased, until the client shuts its side.
fn upperServer(io: Io, listener: *net.Server) !void {
    const stream = try listener.accept(io);
    defer stream.close(io);
    var rbuf: [97]u8 = undefined;
    var wbuf: [61]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    while (true) {
        const b = r.interface.takeByte() catch break;
        try w.interface.writeByte(std.ascii.toUpper(b));
    }
    try w.interface.flush();
}

fn dgramServer(io: Io, sock: net.Socket, n: usize) !void {
    var buf: [256]u8 = undefined;
    for (0..n) |_| {
        const msg = try sock.receive(io, &buf);
        var reply: [257]u8 = undefined;
        reply[0] = @intCast(msg.data.len);
        @memcpy(reply[1..][0..msg.data.len], msg.data);
        try sock.send(io, &msg.from, reply[0 .. msg.data.len + 1]);
    }
}

fn acceptForever(io: Io, listener: *net.Server) !void {
    const s = try listener.accept(io);
    s.close(io);
}

fn program(io: Io, dir: Dir, report: *Report) !void {
    const lo: net.IpAddress = .{ .ip4 = .loopback(0) };

    // A stream: 40 messages of varying size, written and echoed upper-cased.
    var listener = try lo.listen(io, .{});
    defer listener.deinit(io);
    var server = io.async(upperServer, .{ io, &listener });
    {
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var writer_task = io.async(writeMessages, .{ io, stream });
        var rbuf: [53]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        var hash: std.hash.Wyhash = .init(0);
        var chunk: [256]u8 = undefined;
        while (true) {
            const n = r.interface.readSliceShort(&chunk) catch break;
            if (n == 0) break;
            hash.update(chunk[0..n]);
            report.stream_bytes += n;
        }
        try writer_task.await(io);
        report.stream = hash.final();
    }
    try server.await(io);

    // Datagrams: 10 requests, each answered with its length and itself.
    {
        const srv = try lo.bind(io, .{ .mode = .dgram });
        defer srv.close(io);
        const cli = try lo.bind(io, .{ .mode = .dgram });
        defer cli.close(io);
        var answering = io.async(dgramServer, .{ io, srv, 10 });
        var hash: std.hash.Wyhash = .init(0);
        var buf: [300]u8 = undefined;
        for (0..10) |i| {
            var req: [32]u8 = undefined;
            const body = std.fmt.bufPrint(&req, "request {d}", .{i * 7}) catch unreachable;
            try cli.send(io, &srv.address, body);
            const msg = try cli.receive(io, &buf);
            hash.update(msg.data);
            report.dgrams += 1;
        }
        try answering.await(io);
        report.dgram = hash.final();

        // Nobody sends to `cli` any more: a bounded receive times out.
        if (cli.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromMilliseconds(30), .clock = .awake } })) |_| {
            report.silent_receive = error.UnexpectedDatagram;
        } else |err| report.silent_receive = err;
    }

    // An accept nobody satisfies, canceled.
    {
        var l2 = try lo.listen(io, .{});
        defer l2.deinit(io);
        var waiting = io.concurrent(acceptForever, .{ io, &l2 }) catch io.async(acceptForever, .{ io, &l2 });
        try io.sleep(.fromMilliseconds(20), .awake);
        if (waiting.cancel(io)) |_| {} else |err| report.canceled_accept = err;
    }

    // A Unix-domain stream in the abstract namespace (no file to clean up),
    // named at random so parallel runs on the real kernel never collide.
    {
        var rnd: [8]u8 = undefined;
        io.random(&rnd);
        var pb: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&pb, "\x00simio-oracle-{x}", .{std.mem.readInt(u64, &rnd, .little)}) catch unreachable;
        const ua = try net.UnixAddress.init(path);
        var l = try ua.listen(io, .{});
        defer l.deinit(io);
        var echo = io.async(upperServer, .{ io, &l });
        const c = try ua.connect(io);
        defer c.close(io);
        var wbuf: [8]u8 = undefined;
        var w = c.writer(io, &wbuf);
        try w.interface.writeAll("unix path");
        try w.interface.flush();
        try c.shutdown(io, .send);
        var rbuf: [8]u8 = undefined;
        var r = c.reader(io, &rbuf);
        report.unix_len = try r.interface.readSliceShort(&report.unix);
        try echo.await(io);
    }

    // Files: write, sync, rename over an existing name, sync the directory,
    // read back, list.
    {
        try dir.writeFile(io, .{ .sub_path = "old.txt", .data = "stale" });
        const f = try dir.createFile(io, "new.tmp", .{});
        var wbuf: [8]u8 = undefined;
        var fw = f.writer(io, &wbuf);
        try fw.interface.writeAll("fresh contents, ");
        try fw.interface.print("{d} bytes", .{25});
        try fw.interface.flush();
        try f.sync(io);
        f.close(io);
        try Dir.rename(dir, "new.tmp", dir, "old.txt", io);
        const content = try dir.readFile(io, "old.txt", &report.file);
        report.file_len = content.len;

        var names: [4][16]u8 = undefined;
        var lens: [4]usize = undefined;
        var count: usize = 0;
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (count == names.len) break;
            @memcpy(names[count][0..e.name.len], e.name);
            lens[count] = e.name.len;
            count += 1;
        }
        // Sorted, so the order a directory happens to list in does not matter.
        var order: [4]usize = .{ 0, 1, 2, 3 };
        std.mem.sort(usize, order[0..count], .{ &names, &lens }, struct {
            fn lt(ctx: struct { *[4][16]u8, *[4]usize }, a: usize, b: usize) bool {
                return std.mem.lessThan(u8, ctx[0][a][0..ctx[1][a]], ctx[0][b][0..ctx[1][b]]);
            }
        }.lt);
        var w: Io.Writer = .fixed(&report.names);
        for (order[0..count], 0..) |i, k| {
            if (k != 0) try w.writeByte('/');
            try w.writeAll(names[i][0..lens[i]]);
        }
        report.names_len = w.end;
    }
    report.done = true;
}

fn writeMessages(io: Io, stream: net.Stream) !void {
    var wbuf: [41]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    for (0..40) |i| {
        try w.interface.print("message {d}: ", .{i});
        for (0..i * 3) |k| try w.interface.writeByte('a' + @as(u8, @intCast(k % 26)));
        try w.interface.writeByte('\n');
    }
    try w.interface.flush();
    try stream.shutdown(io, .send);
}

// ── the two runs ───────────────────────────────────────────────────────────

fn onSimio(report: *Report) !void {
    var sim: Sim = undefined;
    sim.init(testing.allocator, .{ .seed = 7, .stack_size = 512 * 1024 });
    defer sim.deinit();
    const h = try sim.addHost(.{});
    try h.spawn(program, .{ h.io(), Dir.cwd(), report });
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    if (h.failure) |err| return err;
}

fn onThreaded(report: *Report) !void {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    program(testing.io, tmp.dir, report) catch |err| switch (err) {
        // A sandbox without a loopback interface.
        error.NetworkDown, error.AddressUnavailable => return error.SkipZigTest,
        else => return err,
    };
}

test "differential oracle: one std.Io program gives the same results on Threaded and on simio" {
    var real: Report = .{};
    try onThreaded(&real);
    var simulated: Report = .{};
    try onSimio(&simulated);

    // What both must have seen — so agreement is not two empty reports.
    try testing.expect(real.done);
    try testing.expect(real.stream_bytes > 2000);
    try testing.expectEqual(@as(usize, 10), real.dgrams);
    try testing.expectEqual(@as(?anyerror, error.Timeout), real.silent_receive);
    try testing.expectEqual(@as(?anyerror, error.Canceled), real.canceled_accept);
    try testing.expectEqualStrings("fresh contents, 25 bytes", real.file[0..real.file_len]);
    try testing.expectEqualStrings("old.txt", real.names[0..real.names_len]);
    try testing.expectEqualStrings("UNIX PATH", real.unix[0..real.unix_len]);
    try testing.expectEqual(real.stream_bytes, simulated.stream_bytes);
    try testing.expectEqual(real.stream, simulated.stream);
    try testing.expectEqual(real.dgrams, simulated.dgrams);
    try testing.expectEqual(real.dgram, simulated.dgram);
    try testing.expectEqual(real.silent_receive, simulated.silent_receive);
    try testing.expectEqual(real.canceled_accept, simulated.canceled_accept);
    try testing.expectEqualStrings(real.file[0..real.file_len], simulated.file[0..simulated.file_len]);
    try testing.expectEqualStrings(real.names[0..real.names_len], simulated.names[0..simulated.names_len]);
    try testing.expect(real.eql(&simulated));
}
