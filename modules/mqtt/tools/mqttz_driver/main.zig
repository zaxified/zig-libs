// SPDX-License-Identifier: MIT

//! A third-party MQTT client (karlseguin/mqttz, MIT) driven against our
//! `Broker`: the scenario `tools/interop.zig` runs after it starts a
//! `TcpServer` (`zig build interop-mqtt`). The client is a black box that
//! decodes what the broker writes with its own codec and encodes everything it
//! sends with it, so a broker bug it trips over is one we did not write a test
//! for. Built with Zig 0.16 (the client's own toolchain), see interop.zig.
//!
//!     mqttz-driver <port>
//!
//! Prints `step <name> ok` per step to stderr, exits 0 after the last.

const std = @import("std");
const mqttz = @import("mqttz");

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("FAIL: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn check(cond: bool, comptime what: []const u8) void {
    if (!cond) fail("{s}", .{what});
}

fn stepOk(name: []const u8) void {
    std.debug.print("step {s} ok\n", .{name});
}

/// The next packet within `ms`, or null.
fn next(c: anytype, ms: i32) ?mqttz.Packet {
    return c.readPacket(.{ .timeout = ms }) catch |e| fail("readPacket: {s}", .{@errorName(e)});
}

fn expectConnack(c: anytype, session_present: bool) void {
    const p = next(c, 5000) orelse fail("no CONNACK", .{});
    switch (p) {
        .connack => |a| {
            check(a.reason_code == .success, "CONNACK success");
            check(a.session_present == session_present, "CONNACK session_present");
        },
        else => fail("expected CONNACK, got {s}", .{@tagName(p)}),
    }
}

fn expectSuback(c: anytype, id: u16, granted: []const u8) void {
    const p = next(c, 5000) orelse fail("no SUBACK", .{});
    switch (p) {
        .suback => |s| {
            check(s.packet_identifier == id, "SUBACK packet id");
            check(std.mem.eql(u8, s.results, granted), "SUBACK granted QoS");
        },
        else => fail("expected SUBACK, got {s}", .{@tagName(p)}),
    }
}

/// Wait for a PUBLISH (answering its QoS handshake, so the broker completes
/// it) and return it; anything else is a failure.
fn expectPublish(c: anytype, want_topic: []const u8, message: []const u8, qos: mqttz.QoS, retain: ?bool) void {
    const p = next(c, 5000) orelse fail("no PUBLISH for {s}", .{want_topic});
    switch (p) {
        .publish => |m| {
            check(std.mem.eql(u8, m.topic, want_topic), "PUBLISH topic");
            check(std.mem.eql(u8, m.message, message), "PUBLISH payload");
            check(m.qos == qos, "PUBLISH QoS");
            if (retain) |r| check(m.retain == r, "PUBLISH retain flag");
            switch (m.qos) {
                .at_most_once => {},
                .at_least_once => c.puback(.{}, .{ .packet_identifier = m.packet_identifier.? }) catch |e| fail("puback: {s}", .{@errorName(e)}),
                .exactly_once => {
                    const id = m.packet_identifier.?;
                    c.pubrec(.{}, .{ .packet_identifier = id }) catch |e| fail("pubrec: {s}", .{@errorName(e)});
                    const rel = next(c, 5000) orelse fail("no PUBREL", .{});
                    check(rel == .pubrel and rel.pubrel.packet_identifier == id, "PUBREL for the PUBREC");
                    c.pubcomp(.{}, .{ .packet_identifier = id }) catch |e| fail("pubcomp: {s}", .{@errorName(e)});
                },
            }
        },
        else => fail("expected PUBLISH {s}, got {s}", .{ want_topic, @tagName(p) }),
    }
}

fn expectSilence(c: anytype, what: []const u8) void {
    if (next(c, 500)) |p| fail("{s}: unexpected {s}", .{ what, @tagName(p) });
}

/// Publish and complete the QoS handshake from the publisher's side.
fn publishAcked(c: anytype, pub_topic: []const u8, message: []const u8, qos: mqttz.QoS, retain: bool) void {
    const id = c.publish(.{}, .{ .topic = pub_topic, .message = message, .qos = qos, .retain = retain }) catch |e| fail("publish: {s}", .{@errorName(e)});
    switch (qos) {
        .at_most_once => {},
        .at_least_once => {
            const p = next(c, 5000) orelse fail("no PUBACK", .{});
            check(p == .puback and p.puback.packet_identifier == id.?, "PUBACK for the PUBLISH");
        },
        .exactly_once => {
            const p = next(c, 5000) orelse fail("no PUBREC", .{});
            check(p == .pubrec and p.pubrec.packet_identifier == id.?, "PUBREC for the PUBLISH");
            c.pubrel(.{}, .{ .packet_identifier = id.? }) catch |e| fail("pubrel: {s}", .{@errorName(e)});
            const q = next(c, 5000) orelse fail("no PUBCOMP", .{});
            check(q == .pubcomp and q.pubcomp.packet_identifier == id.?, "PUBCOMP for the PUBREL");
        },
    }
}

/// A subscription's options: 5.0's flags where they exist; 3.1.1's strict
/// client refuses any but the defaults.
fn sub(comptime v5: bool, filter: []const u8, qos: mqttz.QoS) mqttz.SubscribeOpts.Topic {
    if (!v5) return .{ .filter = filter, .qos = qos };
    return .{ .filter = filter, .qos = qos, .no_local = false, .retain_handling = .send_retained_on_subscribe };
}

fn scenario(comptime Client: type, io: std.Io, gpa: std.mem.Allocator, port: u16, comptime label: []const u8) void {
    const v5 = Client == mqttz.posix.Client5;
    const opts: Client.Opts = .{ .port = port, .ip = "127.0.0.1", .allocator = gpa, .default_timeout = 5000 };
    var a = Client.init(io, opts) catch |e| fail("init: {s}", .{@errorName(e)});
    defer a.deinit();
    var b = Client.init(io, opts) catch |e| fail("init: {s}", .{@errorName(e)});

    // A: the subscriber, QoS 2 on `<label>/#` (each scenario has its own topics: the broker keeps retained messages).
    a.connect(.{}, .{ .client_id = label ++ "-a", .keepalive_sec = 30 }) catch |e| fail("connect: {s}", .{@errorName(e)});
    expectConnack(&a, false);
    const sid = a.subscribe(.{}, .{ .topics = &.{sub(v5, label ++ "/#", .exactly_once)} }) catch |e| fail("subscribe: {s}", .{@errorName(e)});
    expectSuback(&a, sid, &.{2});
    stepOk(label ++ " connect + subscribe");

    // B: the publisher, with a Will on `<label>/will`.
    b.connect(.{}, .{ .client_id = label ++ "-b", .keepalive_sec = 30, .will = .{ .topic = label ++ "/will", .message = "bye", .qos = .at_least_once, .retain = false } }) catch |e| fail("connect: {s}", .{@errorName(e)});
    expectConnack(&b, false);
    publishAcked(&b, label ++ "/q0", "zero", .at_most_once, false);
    expectPublish(&a, label ++ "/q0", "zero", .at_most_once, false);
    publishAcked(&b, label ++ "/q1", "one", .at_least_once, false);
    expectPublish(&a, label ++ "/q1", "one", .at_least_once, false);
    publishAcked(&b, label ++ "/q2", "two", .exactly_once, false);
    expectPublish(&a, label ++ "/q2", "two", .exactly_once, false);
    stepOk(label ++ " QoS 0, 1 and 2 end to end");

    // Retained: kept by the broker, sent to a new subscriber with the flag.
    publishAcked(&b, label ++ "/ret", "kept", .at_least_once, true);
    expectPublish(&a, label ++ "/ret", "kept", .at_least_once, null);
    var c = Client.init(io, opts) catch |e| fail("init: {s}", .{@errorName(e)});
    defer c.deinit();
    c.connect(.{}, .{ .client_id = label ++ "-c", .keepalive_sec = 30 }) catch |e| fail("connect: {s}", .{@errorName(e)});
    expectConnack(&c, false);
    const rid = c.subscribe(.{}, .{ .topics = &.{sub(v5, label ++ "/ret", .at_least_once)} }) catch |e| fail("subscribe: {s}", .{@errorName(e)});
    expectSuback(&c, rid, &.{1});
    expectPublish(&c, label ++ "/ret", "kept", .at_least_once, true);
    stepOk(label ++ " retained message");

    // Unsubscribe: nothing arrives afterwards.
    const uid = a.unsubscribe(.{}, .{ .topics = &.{label ++ "/#"} }) catch |e| fail("unsubscribe: {s}", .{@errorName(e)});
    const up = next(&a, 5000) orelse fail("no UNSUBACK", .{});
    check(up == .unsuback and up.unsuback.packet_identifier == uid, "UNSUBACK for the UNSUBSCRIBE");
    // (A PUBLISH nobody takes is answered with PUBACK 0x10, "No matching
    // subscribers", which mqttz's own codec refuses as malformed: C is the
    // subscriber, A must hear nothing.)
    publishAcked(&b, label ++ "/ret", "again", .at_least_once, false);
    expectPublish(&c, label ++ "/ret", "again", .at_least_once, false);
    expectSilence(&a, "after UNSUBSCRIBE");
    stepOk(label ++ " unsubscribe");

    // Keep-alive.
    a.ping(.{}) catch |e| fail("ping: {s}", .{@errorName(e)});
    const pong = next(&a, 5000) orelse fail("no PINGRESP", .{});
    check(pong == .pong, "PINGRESP");
    stepOk(label ++ " ping");

    // The Will: B's connection drops with no DISCONNECT.
    const wid = a.subscribe(.{}, .{ .topics = &.{sub(v5, label ++ "/will", .at_least_once)} }) catch |e| fail("subscribe: {s}", .{@errorName(e)});
    expectSuback(&a, wid, &.{1});
    b.deinit(); // closes the socket, no DISCONNECT
    expectPublish(&a, label ++ "/will", "bye", .at_least_once, false);
    stepOk(label ++ " will on a dropped connection");

    a.disconnect(.{}, .{ .reason = .normal }) catch {};
    c.disconnect(.{}, .{ .reason = .normal }) catch {};
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.skip();
    const port = std.fmt.parseInt(u16, args.next() orelse fail("usage: mqttz-driver <port>", .{}), 10) catch fail("bad port", .{});
    scenario(mqttz.posix.Client5, init.io, init.gpa, port, "v5");
    scenario(mqttz.posix.Client311, init.io, init.gpa, port, "v311");
    std.debug.print("done\n", .{});
}
