// SPDX-License-Identifier: MIT

//! **Live interop against a real third-party BACnet device.**
//!
//! Everything here is gated on `BACNET_TEST_DEVICE=host:port`. With the
//! variable unset — which is the normal case, and what CI does — each test
//! prints `SKIPPED: ...` and passes. Nothing in this file is required for the
//! offline suite, and no test here fabricates a result when no peer answers:
//! a peer that is configured but silent is a **failure**, not a skip.
//!
//! The peer this was developed against is a Python **bacpypes3** virtual
//! device (an independent implementation, used strictly as a black box) bound
//! to `127.0.0.1:47809`, holding a Device object at instance 599, an
//! `analog-input,5` named `ZONE-TEMP` and a writable `analog-value,1` named
//! `SETPOINT`. Any conforming device with those objects works; the object
//! instances are configurable through the environment.
//!
//! One deliberate deviation from a normal client: **Who-Is is sent as a
//! directed unicast** rather than a broadcast. A loopback-bound test device
//! never sees `255.255.255.255`, and every conforming device answers a
//! unicast Who-Is (clause 16.10 puts no restriction on how it arrives). That
//! is what `Client.whoIsTo` exists for.

const std = @import("std");
const types = @import("types.zig");
const tag = @import("tag.zig");
const bvll = @import("bvll.zig");
const service = @import("service.zig");
const transport = @import("transport.zig");
const client = @import("client.zig");

const testing = std.testing;

const Env = struct {
    device: bvll.BipAddress,
    /// Device instance the peer should answer a Who-Is with.
    instance: u32,
    /// A readable analog input.
    sensor: tag.ObjectId,
    /// A writable analog value.
    setpoint: tag.ObjectId,
    /// Local UDP port to bind. Must differ from the peer's when both are on
    /// loopback.
    local_port: u16,
};

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

fn env() ?Env {
    const spec = envVar("BACNET_TEST_DEVICE") orelse return null;
    const addr = bvll.BipAddress.parse(spec) orelse return null;
    return .{
        .device = addr,
        .instance = envInt("BACNET_TEST_INSTANCE", 599),
        .sensor = .{
            .type = .analog_input,
            .instance = @intCast(envInt("BACNET_TEST_AI", 5)),
        },
        .setpoint = .{
            .type = .analog_value,
            .instance = @intCast(envInt("BACNET_TEST_AV", 1)),
        },
        .local_port = @intCast(envInt("BACNET_TEST_LOCAL_PORT", 47810)),
    };
}

fn envInt(name: []const u8, default: u32) u32 {
    const s = envVar(name) orelse return default;
    return std.fmt.parseInt(u32, s, 10) catch default;
}

fn skip(comptime what: []const u8) void {
    std.debug.print(
        "SKIPPED: {s} (set BACNET_TEST_DEVICE=host:port to run)\n",
        .{what},
    );
}

/// Drives the client until it produces something other than `.none`, or the
/// budget runs out. `now_ms` advances by the socket's receive timeout each
/// round, which is a real clock in every way that matters to the APDU timer
/// without needing one.
const poll_step_ms: u32 = 100;
const poll_rounds: usize = 40; // 4 seconds

fn wait(c: anytype, now: *u64) !client.Event {
    var rounds: usize = 0;
    while (rounds < poll_rounds) : (rounds += 1) {
        const ev = try c.poll(now.*);
        if (ev != .none) return ev;
        now.* += poll_step_ms;
    }
    return error.NoResponseFromPeer;
}

const Rig = struct {
    threaded: std.Io.Threaded,
    udp: transport.UdpTransport,
    c: client.DefaultClient,
    e: Env,
    now: u64 = 0,

    fn open(e: Env) !*Rig {
        const rig = try testing.allocator.create(Rig);
        errdefer testing.allocator.destroy(rig);
        rig.* = .{
            .threaded = std.Io.Threaded.init(testing.allocator, .{}),
            .udp = undefined,
            .c = undefined,
            .e = e,
        };
        rig.udp = try transport.UdpTransport.open(rig.threaded.io(), .{
            .port = e.local_port,
            .broadcast_address = e.device,
        });
        rig.udp.setRecvTimeout(poll_step_ms);
        rig.c = client.DefaultClient.init(rig.udp.transport(), .{
            .apdu_timeout_ms = 2000,
            .retries = 1,
        });
        return rig;
    }

    fn close(self: *Rig) void {
        self.udp.close();
        self.threaded.deinit();
        testing.allocator.destroy(self);
    }
};

test "live: Who-Is is answered with I-Am" {
    const e = env() orelse return skip("live Who-Is/I-Am");
    var rig = try Rig.open(e);
    defer rig.close();

    try rig.c.whoIsTo(e.device, null, null);
    const ev = try wait(&rig.c, &rig.now);

    try testing.expectEqual(
        @as(u22, @intCast(e.instance)),
        ev.i_am.info.device.instance,
    );
    try testing.expectEqual(types.ObjectType.device, ev.i_am.info.device.type);
    // Whatever the peer advertises, it must be a code this module accepts.
    try testing.expect(ev.i_am.info.max_apdu_accepted >= 50);
    std.debug.print(
        "live: I-Am device {d}, max-APDU {d}, segmentation {t}, vendor {d}\n",
        .{
            ev.i_am.info.device.instance,
            ev.i_am.info.max_apdu_accepted,
            ev.i_am.info.segmentation,
            ev.i_am.info.vendor_id,
        },
    );
}

test "live: ReadProperty of an analog input's present value and name" {
    const e = env() orelse return skip("live ReadProperty");
    var rig = try Rig.open(e);
    defer rig.close();

    const id = try rig.c.readProperty(e.device, e.sensor, .present_value, null, rig.now);
    const ev = try wait(&rig.c, &rig.now);
    try testing.expectEqual(id, ev.complex_ack.invoke_id);
    try testing.expectEqual(types.ConfirmedService.read_property, ev.complex_ack.svc);
    const ack = try service.ReadPropertyAck.decode(ev.complex_ack.data);
    try testing.expect(ack.object.eql(e.sensor));
    try testing.expectEqual(types.PropertyIdentifier.present_value, ack.property);
    const v = try ack.scalar();
    try testing.expectEqual(tag.ApplicationTag.real, std.meta.activeTag(v));
    std.debug.print("live: present-value = {d}\n", .{v.real});

    // A string property, which exercises the encoding octet.
    _ = try rig.c.readProperty(e.device, e.sensor, .object_name, null, rig.now);
    const ev2 = try wait(&rig.c, &rig.now);
    const ack2 = try service.ReadPropertyAck.decode(ev2.complex_ack.data);
    const name = (try ack2.scalar()).character_string;
    try testing.expectEqual(tag.StringEncoding.utf8, name.encoding);
    try testing.expect(name.asUtf8() != null);
    std.debug.print("live: object-name = \"{s}\"\n", .{name.asUtf8().?});

    // A bit-string property, which exercises the unused-bits octet.
    _ = try rig.c.readProperty(e.device, e.sensor, .status_flags, null, rig.now);
    const ev3 = try wait(&rig.c, &rig.now);
    const ack3 = try service.ReadPropertyAck.decode(ev3.complex_ack.data);
    const bs = (try ack3.scalar()).bit_string;
    try testing.expectEqual(@as(usize, 4), bs.bitCount());
}

test "live: reading a property the device does not have returns an Error PDU" {
    const e = env() orelse return skip("live ReadProperty error");
    var rig = try Rig.open(e);
    defer rig.close();

    // No analog input has a `log-buffer`.
    _ = try rig.c.readProperty(e.device, e.sensor, .log_buffer, null, rig.now);
    const ev = try wait(&rig.c, &rig.now);
    try testing.expectEqual(types.ErrorClass.property, ev.err.class);
    try testing.expectEqual(types.ErrorCode.unknown_property, ev.err.code);

    // ... and an object it does not have.
    _ = try rig.c.readProperty(
        e.device,
        .{ .type = .analog_input, .instance = 4194302 },
        .present_value,
        null,
        rig.now,
    );
    const ev2 = try wait(&rig.c, &rig.now);
    try testing.expectEqual(types.ErrorClass.object, ev2.err.class);
    try testing.expectEqual(types.ErrorCode.unknown_object, ev2.err.code);
}

test "live: WriteProperty changes a value the device then reads back" {
    const e = env() orelse return skip("live WriteProperty");
    var rig = try Rig.open(e);
    defer rig.close();

    // Read the current value so the test restores it afterwards.
    _ = try rig.c.readProperty(e.device, e.setpoint, .present_value, null, rig.now);
    const before = try service.ReadPropertyAck.decode(
        (try wait(&rig.c, &rig.now)).complex_ack.data,
    );
    const original = (try before.scalar()).real;

    const target: f32 = if (original == 22.5) 23.5 else 22.5;
    var vbuf: [8]u8 = undefined;
    var vw = tag.Writer.init(&vbuf);
    try vw.appReal(target);
    const id = try rig.c.writeProperty(
        e.device,
        e.setpoint,
        .present_value,
        null,
        vw.written(),
        null,
        rig.now,
    );
    const ack = try wait(&rig.c, &rig.now);
    try testing.expectEqual(id, ack.simple_ack.invoke_id);
    try testing.expectEqual(types.ConfirmedService.write_property, ack.simple_ack.svc);

    _ = try rig.c.readProperty(e.device, e.setpoint, .present_value, null, rig.now);
    const after = try service.ReadPropertyAck.decode(
        (try wait(&rig.c, &rig.now)).complex_ack.data,
    );
    try testing.expectEqual(target, (try after.scalar()).real);
    std.debug.print("live: wrote {d}, read back {d}\n", .{ target, (try after.scalar()).real });

    // Put it back.
    var rbuf: [8]u8 = undefined;
    var rw = tag.Writer.init(&rbuf);
    try rw.appReal(original);
    _ = try rig.c.writeProperty(
        e.device,
        e.setpoint,
        .present_value,
        null,
        rw.written(),
        null,
        rig.now,
    );
    _ = try wait(&rig.c, &rig.now);
}

test "live: ReadPropertyMultiple over two objects, including a bad property" {
    const e = env() orelse return skip("live ReadPropertyMultiple");
    var rig = try Rig.open(e);
    defer rig.close();

    _ = try rig.c.readPropertyMultiple(e.device, &.{
        .{
            .object = e.sensor,
            .properties = &.{
                .{ .property = .present_value },
                .{ .property = .status_flags },
                .{ .property = .object_name },
                .{ .property = .log_buffer }, // deliberately absent
            },
        },
        .{
            .object = e.setpoint,
            .properties = &.{.{ .property = .present_value }},
        },
    }, rig.now);
    const ev = try wait(&rig.c, &rig.now);
    try testing.expectEqual(
        types.ConfirmedService.read_property_multiple,
        ev.complex_ack.svc,
    );

    var it = service.RpmAckIterator.init(ev.complex_ack.data);
    const r1 = (try it.next()).?;
    try testing.expect(r1.object.eql(e.sensor));
    var els = r1.results();

    const pv = (try els.next()).?;
    try testing.expectEqual(types.PropertyIdentifier.present_value, pv.property);
    var pr = tag.Reader.init(pv.outcome.value);
    _ = (try pr.appValue()).real;

    const sf = (try els.next()).?;
    try testing.expectEqual(types.PropertyIdentifier.status_flags, sf.property);

    const nm = (try els.next()).?;
    try testing.expectEqual(types.PropertyIdentifier.object_name, nm.property);

    // The per-property error, which is the whole reason RPM exists.
    const bad = (try els.next()).?;
    try testing.expectEqual(types.PropertyIdentifier.log_buffer, bad.property);
    try testing.expectEqual(types.ErrorCode.unknown_property, bad.outcome.access_error.code);
    try testing.expectEqual(@as(?service.ResultElement, null), try els.next());

    const r2 = (try it.next()).?;
    try testing.expect(r2.object.eql(e.setpoint));
    try testing.expectEqual(@as(?service.RpmAckIterator.Result, null), try it.next());
    std.debug.print("live: RPM returned both objects with a per-property error\n", .{});
}

test "live: reading the Device object tells us who we are talking to" {
    const e = env() orelse return skip("live Device object read");
    var rig = try Rig.open(e);
    defer rig.close();

    const dev: tag.ObjectId = .{ .type = .device, .instance = @intCast(e.instance) };
    _ = try rig.c.readPropertyMultiple(e.device, &.{.{
        .object = dev,
        .properties = &.{
            .{ .property = .object_name },
            .{ .property = .vendor_identifier },
            .{ .property = .segmentation_supported },
            .{ .property = .max_apdu_length_accepted },
            .{ .property = .protocol_version },
        },
    }}, rig.now);
    const ev = try wait(&rig.c, &rig.now);

    var it = service.RpmAckIterator.init(ev.complex_ack.data);
    var els = (try it.next()).?.results();
    var seen: usize = 0;
    while (try els.next()) |el| : (seen += 1) {
        switch (el.outcome) {
            .value => |v| {
                var r = tag.Reader.init(v);
                _ = try r.appValue();
            },
            .access_error => {},
        }
    }
    try testing.expectEqual(@as(usize, 5), seen);
}

test "live: SubscribeCOV is accepted and the initial notification arrives" {
    const e = env() orelse return skip("live SubscribeCOV");
    var rig = try Rig.open(e);
    defer rig.close();

    const id = try rig.c.subscribeCov(e.device, 7, e.sensor, false, 60, rig.now);
    const ack = try wait(&rig.c, &rig.now);
    // A device that does not support COV answers with an Error, which is a
    // legitimate outcome for a conforming peer and must not fail the test.
    switch (ack) {
        .simple_ack => |s| {
            try testing.expectEqual(id, s.invoke_id);
            try testing.expectEqual(types.ConfirmedService.subscribe_cov, s.svc);
        },
        .err => |er| {
            std.debug.print(
                "live: peer declined COV ({t}/{t}) — accepted as a conforming answer\n",
                .{ er.class, er.code },
            );
            return;
        },
        else => return error.UnexpectedResponse,
    }

    // Clause 13.14.2: a successful subscription is followed immediately by a
    // notification carrying the current value.
    const note = try wait(&rig.c, &rig.now);
    try testing.expectEqual(@as(u32, 7), note.cov.notification.process_id);
    try testing.expect(note.cov.notification.monitored_object.eql(e.sensor));
    var vals = note.cov.notification.values();
    const first = (try vals.next()).?;
    try testing.expectEqual(types.PropertyIdentifier.present_value, first.property);
    std.debug.print("live: COV subscription confirmed, initial notification received\n", .{});

    _ = try rig.c.cancelCov(e.device, 7, e.sensor, rig.now);
    _ = try wait(&rig.c, &rig.now);
}

test "live: our device side answers a real third-party client" {
    // The mirror image: gated separately because it needs the peer to be a
    // *client*, not a device. Set BACNET_TEST_LISTEN=host:port and point a
    // third-party client (e.g. bacpypes3's `read-property` sample) at it.
    const spec = envVar("BACNET_TEST_LISTEN") orelse {
        std.debug.print(
            "SKIPPED: live device side (set BACNET_TEST_LISTEN=host:port and point a real client at it)\n",
            .{},
        );
        return;
    };
    const addr = bvll.BipAddress.parse(spec) orelse return error.BadListenSpec;

    const device = @import("device.zig");
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var udp = try transport.UdpTransport.open(threaded.io(), .{ .port = addr.port });
    defer udp.close();
    udp.setRecvTimeout(poll_step_ms);

    var dev_props = [_]device.Property{
        .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .device, .instance = 599 } } },
        .{ .id = .object_name, .value = .{ .string = "ZIG-BACNET-DEVICE" } },
        .{ .id = .object_type, .value = .{ .enumerated = 8 } },
        .{ .id = .vendor_identifier, .value = .{ .unsigned = 0 } },
        .{ .id = .protocol_version, .value = .{ .unsigned = 1 } },
        .{ .id = .segmentation_supported, .value = .{ .enumerated = 3 } },
    };
    var ai_props = [_]device.Property{
        .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .analog_input, .instance = 5 } } },
        .{ .id = .object_name, .value = .{ .string = "ZONE-TEMP" } },
        .{ .id = .present_value, .value = .{ .real = 72.5 }, .cov_reported = true },
        .{ .id = .status_flags, .value = .{ .bit_string = .{ .unused_bits = 4, .bytes = &.{0x00} } }, .cov_reported = true },
    };
    var objects = [_]device.Object{
        .{ .id = .{ .type = .device, .instance = 599 }, .properties = &dev_props },
        .{ .id = .{ .type = .analog_input, .instance = 5 }, .properties = &ai_props },
    };
    var dev = device.DefaultDevice.init(udp.transport(), .{ .instance = 599 }, &objects);

    std.debug.print("live: device listening on {s}; drive it now\n", .{spec});
    var now: u64 = 0;
    var served: usize = 0;
    var rounds: usize = 0;
    while (rounds < 300) : (rounds += 1) { // 30 seconds
        const ev = try dev.poll(now);
        if (ev != .none) served += 1;
        now += poll_step_ms;
    }
    std.debug.print("live: device served {d} requests\n", .{served});
    try testing.expect(served > 0);
}
