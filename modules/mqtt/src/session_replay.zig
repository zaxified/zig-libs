// SPDX-License-Identifier: MIT

//! **External anchor for the broker's session state: real Mosquitto, replayed.**
//!
//! `testdata/session_transcript.txt` was taken by `tools/session_oracle.py`:
//! scripted MQTT 3.1.1 clients over raw sockets against Eclipse Mosquitto
//! 2.1.2 -- persistent sessions and their offline queue, redelivery of
//! unacknowledged QoS 1/2 messages, QoS 2 duplicate suppression, retained
//! messages, Wills on every way a connection ends, take-over, CONNECT refusals,
//! protocol violations, keep-alive. Here the same client bytes go into a fresh
//! `Broker` per scenario (three of them 5.0: Session Expiry and Will Delay
//! timers), at the recorded clock and in the recorded order, and
//! every connection must receive exactly the bytes Mosquitto sent it and be
//! closed exactly when Mosquitto closed it -- except where `divergences`
//! names a difference both sides of which are MQTT, pinned to our bytes.
//! Divergences were settled by a third and fourth broker (NanoMQ, amqtt:
//! `session_oracle.py --peer`), never by Mosquitto's word alone.
//!
//! The driver here plays `TcpServer`'s part: a connection whose `process`
//! fails or returns `.close`, or whose transport the broker closed (take-over),
//! is `remove`d; a keep-alive past 1.5 × is removed at the next step; a `tick`
//! line (the oracle paused) runs the periodic `expireSessions` /
//! `publishDueWills`.

const std = @import("std");
const testing = std.testing;
const broker_mod = @import("broker.zig");

const transcript = @embedFile("testdata/session_transcript.txt");

const Sink = struct {
    gpa: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,
    closed: bool = false,

    fn transport(s: *Sink) broker_mod.Transport {
        return .{ .ctx = s, .writeFn = writeFn, .closeFn = closeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) broker_mod.TransportError!void {
        const s: *Sink = @ptrCast(@alignCast(ctx));
        s.out.appendSlice(s.gpa, bytes) catch return error.TransportFailed;
    }

    fn closeFn(ctx: *anyopaque) void {
        const s: *Sink = @ptrCast(@alignCast(ctx));
        s.closed = true;
    }
};

const max_conns = 8;

/// Where this broker answers differently from Mosquitto and both answers are
/// MQTT. Each is pinned to OUR bytes, so a change on either side shows.
const Divergence = struct { scenario: []const u8, conn: usize, ours: []const u8, why: []const u8 };
const divergences = [_]Divergence{.{
    .scenario = "overlapping",
    .conn = 0,
    .ours = "20020000" ++ "900400010001" ++ "320b00036f2f78000173656c66" ++ "40020001",
    .why = "a message matching two of one client's subscriptions: 3.1.1 3.3.5-1 " ++
        "requires one copy at the higher QoS, which is what this broker sends; " ++
        "Mosquitto adds a second copy per further subscription, which 3.3.5 " ++
        "permits (NanoMQ and amqtt send two as well, in another order)",
}};

const Scenario = struct {
    name: []const u8,
    b: broker_mod.Broker,
    sinks: [max_conns]Sink,
    conns: [max_conns]?*broker_mod.Connection = @splat(null),
    /// The broker ended it (as opposed to the client dropping it).
    server_closed: [max_conns]bool = @splat(false),
    /// The connection existed and is over, either way.
    over: [max_conns]bool = @splat(false),
    /// Its CONNECT was 5.0 (a `v5` line): CONNACKs compare by flags and
    /// reason code, see `withoutConnackProperties`.
    v5: [max_conns]bool = @splat(false),

    fn init(s: *Scenario, arena: std.mem.Allocator, name: []const u8) void {
        s.* = .{ .name = name, .b = broker_mod.Broker.init(testing.allocator, .{}), .sinks = undefined };
        for (&s.sinks) |*k| k.* = .{ .gpa = arena };
    }

    fn end(s: *Scenario, i: usize, by_server: bool) void {
        s.b.remove(s.conns[i].?);
        s.conns[i] = null;
        s.over[i] = true;
        s.server_closed[i] = by_server;
    }

    /// What `TcpServer` does between reads: drop what the broker closed and
    /// what outlived its keep-alive.
    fn sweep(s: *Scenario, now: i64) void {
        for (0..max_conns) |i| {
            const c = s.conns[i] orelse continue;
            if (s.sinks[i].closed or s.b.keepAliveExpired(c, now)) s.end(i, true);
        }
    }
};

/// A 5.0 CONNACK's properties announce the broker's own configuration
/// (Mosquitto: Topic Alias Maximum 10, Maximum Packet Size, Receive Maximum;
/// this broker: its `Config`), not session state -- so on a 5.0 connection
/// each CONNACK is cut to its flags and reason code before comparing.
fn withoutConnackProperties(gpa: std.mem.Allocator, stream: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var off: usize = 0;
    while (off < stream.len) {
        var len: usize = 0;
        var shift: u5 = 0;
        var i = off + 1;
        while (true) : (i += 1) {
            len |= @as(usize, stream[i] & 0x7f) << shift;
            if (stream[i] & 0x80 == 0) break;
            shift += 7;
        }
        const end = i + 1 + len;
        if (stream[off] == 0x20 and len >= 2) {
            try out.appendSlice(gpa, &.{ 0x20, 0x02, stream[i + 1], stream[i + 2] });
        } else try out.appendSlice(gpa, stream[off..end]);
        off = end;
    }
    return out.toOwnedSlice(gpa);
}

fn unhex(gpa: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

test "session replay: every scenario reproduces what Mosquitto sent and when it closed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var s: Scenario = undefined;
    var live = false;
    var scenarios: usize = 0;
    var mismatches: usize = 0;
    var listed: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, transcript, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const head = f.next() orelse continue;
        if (std.mem.eql(u8, head, "scenario")) {
            s.init(arena, f.next().?);
            live = true;
            scenarios += 1;
        } else if (std.mem.eql(u8, head, "end")) {
            for (0..max_conns) |i| if (s.conns[i] != null) s.end(i, false);
            s.b.deinit();
            live = false;
        } else if (std.mem.eql(u8, head, "v5")) {
            s.v5[try std.fmt.parseInt(usize, f.next().?, 10)] = true;
        } else if (std.mem.eql(u8, head, "at")) {
            const now = try std.fmt.parseInt(i64, f.next().?, 10);
            const what = f.next().?;
            if (std.mem.eql(u8, what, "tick")) {
                s.sweep(now);
                _ = s.b.expireSessions(now);
                _ = s.b.publishDueWills(now);
                continue;
            }
            const i = try std.fmt.parseInt(usize, f.next().?, 10);
            const dir = f.next().?;
            s.sweep(now);
            if (std.mem.eql(u8, dir, "close")) {
                if (s.conns[i] != null) s.end(i, false);
                continue;
            }
            if (s.over[i]) {
                // Mosquitto still had it open here: the oracle never writes
                // to a connection the broker closed.
                std.debug.print("{s}: conn {d} closed by the broker before Mosquitto would\n", .{ s.name, i });
                mismatches += 1;
                continue;
            }
            if (s.conns[i] == null) s.conns[i] = try s.b.accept(s.sinks[i].transport());
            const c = s.conns[i].?;
            try s.b.feed(c, try unhex(arena, f.next() orelse ""));
            const disp = s.b.process(c, now) catch .close;
            if (disp == .close) s.end(i, true);
            s.sweep(now);
        } else if (std.mem.eql(u8, head, "out")) {
            const i = try std.fmt.parseInt(usize, f.next().?, 10);
            var want = try unhex(arena, f.next() orelse "");
            var ours = s.sinks[i].out.items;
            if (s.v5[i]) {
                want = try withoutConnackProperties(arena, want);
                ours = try withoutConnackProperties(arena, ours);
            }
            const known = for (divergences) |d| {
                if (std.mem.eql(u8, d.scenario, s.name) and d.conn == i) break d;
            } else null;
            if (known) |d| {
                if (std.mem.eql(u8, try unhex(arena, d.ours), ours)) {
                    listed += 1;
                } else {
                    std.debug.print("{s}: conn {d} listed divergence no longer holds\n  listed {s}\n  ours   {x}\n", .{ s.name, i, d.ours, ours });
                    mismatches += 1;
                }
            } else if (!std.mem.eql(u8, want, ours)) {
                std.debug.print("{s}: conn {d} output differs\n  mosquitto {x}\n  ours      {x}\n", .{ s.name, i, want, ours });
                mismatches += 1;
            }
        } else if (std.mem.eql(u8, head, "closed")) {
            const i = try std.fmt.parseInt(usize, f.next().?, 10);
            const want = std.mem.eql(u8, f.next().?, "1");
            if (want != s.server_closed[i]) {
                std.debug.print("{s}: conn {d} closed by the broker: mosquitto {}, ours {}\n", .{ s.name, i, want, s.server_closed[i] });
                mismatches += 1;
            }
        }
    }
    try testing.expect(!live);
    try testing.expectEqual(@as(usize, 23), scenarios);
    try testing.expectEqual(@as(usize, 0), mismatches);
    try testing.expectEqual(divergences.len, listed);
}
