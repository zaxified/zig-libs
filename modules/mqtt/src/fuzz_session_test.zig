// SPDX-License-Identifier: MIT

//! Deterministic fuzz harnesses for the 2026-10-17 code (driver
//! `MQTT_FUZZ`, testkit; `_ONLY` picks one by name):
//!
//! - `mqtt-acl-parse` — damaged `acl_file` and `password_file` texts through
//!   `acl.Acl.parse` / `acl.Passwords.parse`, then every parsed rule set asked
//!   about requests drawn from a small topic alphabet. Invariants: no panic, a
//!   parsed rule never points outside the text, `deny #` (when parsed for the
//!   anonymous scope) refuses every anonymous request. Passwords are verified
//!   only for the real `mosquitto_passwd` goldens (a damaged line can ask for
//!   ten million PBKDF2 iterations; the parser bounds that, a fuzz run must not
//!   pay it per input).
//! - `mqtt-broker-session` — a `Broker` with a random `Config` (retain off,
//!   payload format checks, delivery ACL, small queues, a keep-alive limit, an
//!   extended-auth hook scripted by the input) driven by a random stream of
//!   5.0 packets on one connection (CONNECT with or without an
//!   Authentication Method, AUTH continue / re-auth with the same or another
//!   method, PUBLISH at every QoS with and without RETAIN and a Payload
//!   Format, SUBSCRIBE, UNSUBSCRIBE, acks for ids that may not exist,
//!   PINGREQ, DISCONNECT, raw damaged bytes), plus a second, never-acking
//!   QoS 1 subscriber so fan-out and the per-connection queue work; the
//!   CONNECT may carry a Will (wildcard, `$SYS`, retained), and the client's
//!   transport may start failing after a few bytes. Invariants:
//!   no panic, every `process` ends in a value or an error, the broker tears
//!   both connections down and `deinit` frees everything (`testing.allocator`
//!   reports a leak as a failure).
//! - `mqtt-broker-multi` — three connection slots sharing three client ids,
//!   3.1.1 and 5.0, persistent sessions (resume, take-over, Session Expiry),
//!   delayed Wills, the retained store and session queues under small caps, a
//!   publish tap that refuses, and transports (subscribers' too) that start
//!   failing mid-exchange, with broker ticks between the packets. Invariants:
//!   no panic, the session / queue / retained caps hold, and `deinit` frees
//!   everything.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const mqtt = @import("root.zig");
const packet = mqtt.packet;
const acl = mqtt.acl;
const fuzz_driver = testkit.fuzz.driver;
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;

fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

        fn mark(comptime l: Label) void {
            counts[@backingInt(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: Rng = .{ .r = prng.random() };
                // One allocator per seed: the 0.17 `testing.allocator` never
                // reuses memory, so 400 seeds on it only grow (cf. testkit
                // fuzz_driver.runSeedsReporting). Leaks still fail per seed.
                var seed_alloc: std.heap.SafeAllocator = .init(testing.allocator, .{ .stack_trace_frames = 0 });
                harness(Rng, &rng, seed_alloc.allocator()) catch |err| {
                    _ = seed_alloc.deinitLog(false);
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
                if (seed_alloc.deinit() != 0) {
                    std.debug.print(name ++ " seed {d}: memory leak\n", .{seed});
                    return error.MemoryLeakDetected;
                }
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @fromBackingInt(@intCast(i))), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

/// `text` with 0–3 octets replaced from the alphabet the formats use, maybe cut.
fn damage(k: *Cursor, text: []const u8, buf: []u8) []u8 {
    const alphabet = "topic user pattern read write readwrite deny # + / %u %c\n:$7$1000=";
    var n = @min(text.len, buf.len);
    @memcpy(buf[0..n], text[0..n]);
    for (0..k.ranged(0, 3)) |_| {
        if (n == 0) break;
        buf[k.ranged(0, @intCast(n - 1))] = alphabet[k.ranged(0, alphabet.len - 1)];
    }
    if (k.ranged(0, 3) == 0) n = k.ranged(0, @intCast(n));
    return buf[0..n];
}

// ── acl ─────────────────────────────────────────────────────────────────

const AclMark = Marker(enum { acl_parsed, acl_refused, pw_parsed, pw_refused, allowed, denied, golden_verified });

const acl_corpus = [_][]const u8{
    "topic read public/#\ntopic deny #\n",
    "topic readwrite sensors/+/temp\nuser alice\ntopic write cmd/alice/#\npattern read devices/%u/#\npattern readwrite clients/%c/#\n",
    "# comment\n\ntopic deny private/+\nuser bob\ntopic read #\ntopic deny secret/#\n",
    "user carol\npattern write %u/%c/out\ntopic read $SYS/#\n",
};

const golden_passwd =
    "alice:$7$1000$aVdP5TwRZIFzLGb8rViI1k6ir2ldLZamfpOm9Av4n0QzEQsO7s6qVsXb9qy8LAy3V0kIG7dqu9T+yxdsCwTcRw==$hdd22TxC7KfyRQBDDQMmcoWz3nwFxlhMdwh45yQsryyMx/ffsn+AqUhLle2+HQeBiA1SWT+DFrDiBqV9xRya0Q==\n" ++
    "bob:$7$1000$AdPRuou8DmEDG7SizhAjrmHJk94sE28EL96MplcRW3GWofUi9cyHDpl20p0STCFvX+XDgUwKS0IuX5vaMU3Ckg==$jn0M3dNRPYhYpWOfsFHQVZJZc0XulVhPZD5Do8iAGJ0qH7G6wdWRd9rFb1WUbIfAD395dO/0HWm3L189aObziw==\n";

const topics = [_][]const u8{ "public/a", "private/x", "secret/k", "sensors/1/temp", "cmd/alice/go", "devices/alice/t", "clients/c1/x", "$SYS/broker/uptime", "a/b/c", "alice/c1/out" };
const filters = [_][]const u8{ "#", "+/x", "public/#", "private/#", "sensors/+/temp", "$SYS/#", "a/+/c", "devices/alice/#" };

fn aclSmith(_: void, s: *testing.Smith) !void {
    return fuzzAcl(testing.Smith, s, testing.allocator);
}
test "fuzz: acl and password files, damaged, parse and answer without panicking" {
    try testing.fuzz({}, aclSmith, .{});
}
test "fuzz driver: MQTT_FUZZ (acl)" {
    try fuzz_driver.run(fuzzAcl, .{ .prefix = "MQTT_FUZZ", .name = "mqtt-acl-parse" });
}
test "fuzz harness: acl, 400 seeds, reaches every outcome" {
    try AclMark.reach(fuzzAcl, "mqtt-acl-parse", 400);
}

fn fuzzAcl(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [256]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };

    var text_buf: [512]u8 = undefined;
    const text = damage(&k, acl_corpus[k.ranged(0, acl_corpus.len - 1)], &text_buf);
    var rules: [16]acl.Rule = undefined;
    if (acl.Acl.parse(text, &rules)) |a| {
        AclMark.mark(.acl_parsed);
        for (a.rules) |r| {
            const p = @intFromPtr(r.topic.ptr);
            if (r.topic.len > 0 and (p < @intFromPtr(text.ptr) or p + r.topic.len > @intFromPtr(text.ptr) + text.len))
                return error.RuleOutsideText;
        }
        const denies_all = std.mem.find(u8, text, "topic deny #\n") != null and
            std.mem.find(u8, text[0..(std.mem.find(u8, text, "topic deny #\n").?)], "user ") == null;
        for (0..8) |_| {
            const op: mqtt.broker.Operation = if (k.byte() & 1 == 0) .publish else .subscribe;
            const anonymous = k.byte() & 1 == 0;
            const req: mqtt.broker.AclRequest = .{
                .client_id = if (k.byte() & 1 == 0) "c1" else "carol",
                .username = if (anonymous) null else switch (k.ranged(0, 2)) {
                    0 => "alice",
                    1 => "bob",
                    else => "carol",
                },
                .topic = if (op == .publish) topics[k.ranged(0, topics.len - 1)] else filters[k.ranged(0, filters.len - 1)],
                .operation = op,
                .retain = k.byte() & 1 == 0,
            };
            const ok = a.check(req);
            if (ok) AclMark.mark(.allowed) else AclMark.mark(.denied);
            if (ok and anonymous and denies_all) return error.DenyAllAllowed;
        }
    } else |_| AclMark.mark(.acl_refused);

    var pw_buf: [512]u8 = undefined;
    const pw_text = damage(&k, golden_passwd, &pw_buf);
    var entries: [4]acl.Entry = undefined;
    if (acl.Passwords.parse(pw_text, &entries)) |_| AclMark.mark(.pw_parsed) else |_| AclMark.mark(.pw_refused);

    // The goldens, intact, once in a while (PBKDF2 at 1000 iterations is the
    // dear part of this harness).
    if (k.ranged(0, 15) == 0) {
        const p = try acl.Passwords.parse(golden_passwd, &entries);
        if (!p.verify("bob", "hunter2") or p.verify("bob", "hunter3")) return error.GoldenBroken;
        AclMark.mark(.golden_verified);
    }
}

// ── broker session ──────────────────────────────────────────────────────

const SessMark = Marker(enum {
    connected,
    refused,
    auth_continued,
    /// An AUTH that ended the connection (a deny, a method mismatch, AUTH out of sequence).
    auth_ended,
    reauth,
    published,
    protocol_error,
    closed_by_broker,
    queued_for_slow_subscriber,
});

const Sink = struct {
    bytes: usize = 0,
    /// Fail every write once this many bytes went out (a client that
    /// vanishes mid-exchange); null = never.
    fail_after: ?usize = null,
    fn transport(s: *Sink) mqtt.broker.Transport {
        return .{ .ctx = s, .writeFn = writeFn };
    }
    fn writeFn(ctx: *anyopaque, b: []const u8) mqtt.broker.TransportError!void {
        const s: *Sink = @ptrCast(@alignCast(ctx));
        if (s.fail_after) |limit| if (s.bytes >= limit) return error.TransportFailed;
        s.bytes += b.len;
    }
};

/// The extended-auth hook: the first octet of the client's data decides.
fn extAuth(_: ?*anyopaque, req: mqtt.broker.ExtAuthRequest) mqtt.broker.ExtAuthResult {
    if (!std.mem.eql(u8, req.method, "FUZZ")) return .unsupported_method;
    req.state[0] +%= 1;
    const d = req.data orelse return .{ .continue_auth = "more" };
    if (d.len == 0) return .deny;
    return switch (d[0] % 4) {
        0 => .{ .success = "done" },
        1 => .{ .continue_auth = "again" },
        2 => .deny,
        else => .unsupported_method,
    };
}

fn denySecret(_: ?*anyopaque, req: mqtt.broker.AclRequest) bool {
    return !std.mem.startsWith(u8, req.topic, "secret/");
}

const will_topics = [_][]const u8{ "w/x", "w/#", "w/+/y", "$SYS/forged", "" };

fn sessionSmith(_: void, s: *testing.Smith) !void {
    return fuzzSession(testing.Smith, s, testing.allocator);
}
test "fuzz: broker under random 5.0 packet streams with extended auth, ACL, limits and a slow subscriber" {
    try testing.fuzz({}, sessionSmith, .{});
}
test "fuzz driver: MQTT_FUZZ (session)" {
    try fuzz_driver.run(fuzzSession, .{ .prefix = "MQTT_FUZZ", .name = "mqtt-broker-session" });
}
test "fuzz harness: session, 400 seeds, reaches every outcome" {
    try SessMark.reach(fuzzSession, "mqtt-broker-session", 400);
}

fn fuzzSession(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [512]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };

    var broker: mqtt.Broker = .init(gpa, .{
        .retain_available = k.byte() & 3 != 0,
        .validate_payload_format = k.byte() & 1 == 0,
        .acl_check_delivery = k.byte() & 1 == 0,
        .authorizeFn = denySecret,
        .extendedAuthFn = if (k.byte() & 3 != 0) extAuth else null,
        .max_keepalive_s = if (k.byte() & 1 == 0) 0 else 30,
        .max_queued_messages = k.ranged(1, 3),
        .max_queued_bytes = 4096,
        .topic_alias_maximum = 4,
    });
    defer broker.deinit();

    // The slow subscriber: QoS 1, never acks, a Receive Maximum of 2.
    var slow_sink: Sink = .{};
    const slow = try broker.accept(slow_sink.transport());
    defer broker.remove(slow);
    {
        var buf: [256]u8 = undefined;
        try broker.feed(slow, try packet.encodeConnect(&buf, .{ .client_id = "slow", .version = .v5, .properties = .{ .receive_maximum = 2 } }));
        _ = try broker.process(slow, 0);
        try broker.feed(slow, try packet.encodePacket(&buf, .v5, .{ .subscribe = .{ .packet_id = 1, .filters = &.{.{ .filter = "#", .qos = .at_least_once }} } }));
        _ = try broker.process(slow, 0);
    }

    var sink: Sink = .{ .fail_after = if (k.ranged(0, 3) == 0) k.ranged(0, 64) else null };
    const conn = try broker.accept(sink.transport());
    defer broker.remove(conn);

    const methods = [_][]const u8{ "FUZZ", "OTHER" };
    var buf: [512]u8 = undefined;
    var now: i64 = 0;
    const steps = k.ranged(1, 24);
    for (0..steps) |step| {
        now += k.ranged(0, 2000);
        var data: [8]u8 = undefined;
        for (&data) |*d| d.* = k.byte();
        const bytes: []const u8 = if (step == 0) try packet.encodeConnect(&buf, .{
            .client_id = if (k.byte() & 3 == 0) "" else "fuzzer",
            .version = .v5,
            .clean_session = k.byte() & 1 == 0,
            .keep_alive_s = @intCast(k.ranged(0, 60)),
            .username = if (k.byte() & 1 == 0) "u" else null,
            .password = if (k.byte() & 1 == 0) "p" else null,
            .will = if (k.ranged(0, 2) == 0) .{
                .topic = will_topics[k.ranged(0, will_topics.len - 1)],
                .message = "gone",
                .qos = @fromBackingInt(@intCast(k.ranged(0, 2))),
                .retain = k.byte() & 1 == 0,
            } else null,
            .properties = if (k.byte() & 1 == 0) .{
                .authentication_method = methods[k.ranged(0, 1)],
                .authentication_data = if (k.byte() & 1 == 0) data[0..k.ranged(0, 8)] else null,
            } else .{},
        }) else switch (k.ranged(0, 14)) {
            0, 1 => try packet.encodePacket(&buf, .v5, .{ .auth = .{
                .reason_code = if (k.byte() & 1 == 0) .continue_authentication else .re_authenticate,
                .properties = .{ .authentication_method = methods[k.ranged(0, 1)], .authentication_data = data[0..k.ranged(0, 8)] },
            } }),
            2, 3, 4, 11, 12, 13 => blk: {
                const qos: packet.QoS = @fromBackingInt(@intCast(k.ranged(0, 2)));
                const utf8 = k.byte() & 1 == 0;
                break :blk try packet.encodePacket(&buf, .v5, .{ .publish = .{
                    .topic = topics[k.ranged(0, topics.len - 1)],
                    .payload = if (utf8) "ok" else "\xff\xfe",
                    .qos = qos,
                    .retain = k.byte() & 1 == 0,
                    .packet_id = if (qos == .at_most_once) 0 else @intCast(k.ranged(1, 4)),
                    .properties = .{ .payload_format = if (k.byte() & 1 == 0) .utf8 else null },
                } });
            },
            5 => try packet.encodePacket(&buf, .v5, .{ .subscribe = .{ .packet_id = @intCast(k.ranged(1, 4)), .filters = &.{.{ .filter = filters[k.ranged(0, filters.len - 1)], .qos = @fromBackingInt(@intCast(k.ranged(0, 2))) }} } }),
            6 => try packet.encodePacket(&buf, .v5, .{ .unsubscribe = .{ .packet_id = @intCast(k.ranged(1, 4)), .filters = &.{filters[k.ranged(0, filters.len - 1)]} } }),
            7 => try packet.encodePacket(&buf, .v5, .{ .puback = .{ .packet_id = @intCast(k.ranged(1, 4)) } }),
            8 => try packet.encodePacket(&buf, .v5, .{ .pubrel = .{ .packet_id = @intCast(k.ranged(1, 4)) } }),
            9 => try packet.encodePingreq(&buf),
            10 => try packet.encodePacket(&buf, .v5, .{ .disconnect = .{} }),
            else => buf[0..k.ranged(1, 8)], // raw bytes (14)
        };
        if (step == 0 and (k.byte() & 7 == 0)) {
            // A damaged CONNECT now and then.
            const m = @constCast(bytes);
            if (m.len > 3) m[k.ranged(2, @intCast(m.len - 1))] = k.byte();
        }
        broker.feed(conn, bytes) catch break;
        const is_auth = step > 0 and bytes.len > 0 and bytes[0] >> 4 == 15;
        const disp = broker.process(conn, now) catch |e| {
            if (is_auth) SessMark.mark(.auth_ended) else if (e == error.ProtocolViolation or e == error.MalformedPacket) SessMark.mark(.protocol_error);
            break;
        };
        if (step == 0) {
            if (conn.state == .connected) SessMark.mark(.connected) else if (disp == .close) SessMark.mark(.refused) else SessMark.mark(.auth_continued);
        } else if (is_auth) {
            if (disp == .close) SessMark.mark(.auth_ended) else if (conn.state == .connected) SessMark.mark(.reauth);
        } else if (bytes.len > 0 and bytes[0] >> 4 == 3 and conn.state == .connected) SessMark.mark(.published);
        if (disp == .close) {
            SessMark.mark(.closed_by_broker);
            break;
        }
    }
    // The slow subscriber's queue (cap 1..8) overflowed: it was queueing.
    if (broker.queueDrops() > 0) SessMark.mark(.queued_for_slow_subscriber);
}

// ── many connections, persistent sessions, transports that fail ─────────

const MultiMark = Marker(enum {
    connected_v3,
    connected_v5,
    session_resumed,
    /// A second connection took a client id from a live one.
    took_over,
    /// A connection ended because a write to it failed.
    write_failed,
    /// A message was queued for a persistent session with no connection.
    queued_offline,
    delayed_will_published,
    retained_stored,
});

/// A tap that refuses, consumes or accepts by the payload length.
fn multiTap(_: ?*anyopaque, _: []const u8, payload: []const u8, _: packet.QoS, _: bool) mqtt.PublishVerdict {
    return switch (payload.len) {
        6 => .refuse,
        5 => .consume,
        else => .accept,
    };
}

const multi_ids = [_][]const u8{ "ca", "cb", "cc" };
const multi_topics = [_][]const u8{ "a/b", "a/c", "w/x", "$SYS/x", "t" };
const multi_filters = [_][]const u8{ "#", "a/+", "a/b", "w/#", "$share/g/a/+", "$SYS/#", "+/b", "t" };

const MultiSlot = struct {
    sink: Sink = .{},
    conn: ?*mqtt.Connection = null,
    v5: bool = false,
};

fn multiSmith(_: void, s: *testing.Smith) !void {
    return fuzzMulti(testing.Smith, s, testing.allocator);
}
test "fuzz: broker with three clients sharing ids, persistent sessions, Wills and transports that fail" {
    try testing.fuzz({}, multiSmith, .{});
}
test "fuzz driver: MQTT_FUZZ (multi)" {
    try fuzz_driver.run(fuzzMulti, .{ .prefix = "MQTT_FUZZ", .name = "mqtt-broker-multi" });
}
test "fuzz harness: multi, 400 seeds, reaches every outcome" {
    try MultiMark.reach(fuzzMulti, "mqtt-broker-multi", 400);
}

/// The CML lesson behind this harness: `mqtt-broker-session` drives ONE
/// client, 5.0 only, and its failing transport is the publisher's — so the
/// teardown of a SUBSCRIBER whose write fails, a persistent session that
/// outlives a connection and is resumed or taken over, delayed Wills and 3.1.1
/// (what a small IoT gateway speaks) were not under it. Three slots share
/// three client ids; every step connects, speaks, drops or ticks the broker.
/// Invariants: nothing panics, the caps hold (sessions, queue, retained
/// bytes), and `deinit` frees everything (the allocator reports a leak or a
/// double free).
fn fuzzMulti(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [512]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };

    const max_sessions = k.ranged(1, 3);
    const max_queued = k.ranged(1, 3);
    var broker: mqtt.Broker = .init(gpa, .{
        .max_packet_size = 1024,
        .max_sessions = max_sessions,
        .max_queued_messages = max_queued,
        .max_queued_bytes = 4096,
        .max_retained = k.ranged(1, 3),
        .max_retained_store_bytes = 256,
        .maximum_qos = if (k.byte() & 3 == 0) .at_least_once else .exactly_once,
        .session_expiry_ms = if (k.byte() & 1 == 0) 0 else 3000,
        .retain_expiry_interval_ms = if (k.byte() & 1 == 0) 0 else 2000,
        .queue_qos0_messages = k.byte() & 1 == 0,
        .tap_wills = k.byte() & 1 == 0,
        .onPublishFn = if (k.byte() & 1 == 0) multiTap else null,
        .sys_interval_ms = 1000,
        .topic_alias_maximum = 2,
    });
    defer broker.deinit();

    var slots: [3]MultiSlot = @splat(.{});
    defer for (&slots) |*s| if (s.conn) |c| broker.remove(c);

    var buf: [512]u8 = undefined;
    var now: i64 = 0;
    // Half the inputs start from a 5.0 client with a kept session and a Will
    // Delay that vanishes: the delayed Will is rare to reach by chance.
    if (k.byte() & 1 == 0) {
        const slot = &slots[0];
        slot.v5 = true;
        const c = try broker.accept(slot.sink.transport());
        slot.conn = c;
        const bytes = try packet.encodeConnect(&buf, .{
            .client_id = multi_ids[k.ranged(0, multi_ids.len - 1)],
            .version = .v5,
            .clean_session = false,
            .will = .{ .topic = "w/x", .message = "gone", .properties = .{ .will_delay_interval = 1 } },
            .properties = .{ .session_expiry_interval = 0xFFFF_FFFF },
        });
        try multiStep(&broker, slot, bytes, now);
        if (slot.conn != null) {
            broker.remove(slot.conn.?);
            slot.conn = null;
            if (k.byte() & 1 == 0) {
                if (broker.publishDueWills(now + 1500) > 0) MultiMark.mark(.delayed_will_published);
            }
        }
    }

    const steps = k.ranged(1, 40);
    for (0..steps) |_| {
        now += k.ranged(0, 1500);
        const slot = &slots[k.ranged(0, slots.len - 1)];
        const action = k.ranged(0, 19);

        // Broker-level ticks, with or without a connection in the slot.
        switch (action) {
            16 => {
                _ = broker.expireSessions(now + k.ranged(0, 5000));
                continue;
            },
            17 => {
                if (broker.publishDueWills(now + k.ranged(0, 4000)) > 0) MultiMark.mark(.delayed_will_published);
                _ = broker.publishSys(now);
                continue;
            },
            18 => {
                broker.publish(multi_topics[k.ranged(0, 2)], "srv", @fromBackingInt(@intCast(k.ranged(0, 1))), k.byte() & 1 == 0) catch {};
                var arena: std.heap.ArenaAllocator = .init(gpa);
                defer arena.deinit();
                _ = try broker.sessionStatesWith(arena.allocator(), .{ .messages = true, .now = now });
                _ = try broker.retainedMessages(arena.allocator(), now);
                continue;
            },
            else => {},
        }

        const conn = slot.conn orelse {
            // Connect: a client id from a pool the other slots share.
            slot.v5 = k.byte() & 1 == 0;
            slot.sink = .{ .fail_after = if (k.ranged(0, 3) == 0) k.ranged(0, 300) else null };
            const c = broker.accept(slot.sink.transport()) catch continue;
            slot.conn = c;
            const will_on = k.ranged(0, 1) == 0;
            const sei: ?u32 = switch (k.ranged(0, 3)) {
                0 => null,
                1 => 4,
                else => 0xFFFF_FFFF,
            };
            const will_delay: ?u32 = switch (k.ranged(0, 3)) {
                0 => null,
                1 => 1,
                else => 3,
            };
            const bytes = packet.encodeConnect(&buf, .{
                .client_id = multi_ids[k.ranged(0, multi_ids.len - 1)],
                .version = if (slot.v5) .v5 else .v3_1_1,
                .clean_session = k.byte() & 1 == 0,
                .keep_alive_s = @intCast(k.ranged(0, 10)),
                .will = if (will_on) .{
                    .topic = multi_topics[k.ranged(0, 2)],
                    .message = "gone",
                    .qos = @fromBackingInt(@intCast(k.ranged(0, 1))),
                    .retain = k.byte() & 1 == 0,
                    .properties = if (slot.v5) .{ .will_delay_interval = will_delay, .message_expiry_interval = if (k.byte() & 1 == 0) 2 else null } else .{},
                } else null,
                .properties = if (slot.v5) .{ .session_expiry_interval = sei } else .{},
            }) catch continue;
            try multiStep(&broker, slot, bytes, now);
            if (slot.conn) |cc| if (cc.state == .connected) {
                if (slot.v5) MultiMark.mark(.connected_v5) else MultiMark.mark(.connected_v3);
                if (broker.sessionQueued(cc.clientId()) != null) MultiMark.mark(.session_resumed);
                // A connection the take-over superseded: its owner thread
                // would see the closed socket and reap it.
                for (&slots) |*o| if (o != slot) if (o.conn) |oc| if (oc.state == .disconnected) {
                    MultiMark.mark(.took_over);
                    broker.remove(oc);
                    o.conn = null;
                };
            };
            continue;
        };

        const v: packet.Version = if (slot.v5) .v5 else .v3_1_1;
        const id: u16 = @intCast(k.ranged(1, 4));
        const bytes: []const u8 = switch (action) {
            0, 1, 2, 3 => blk: {
                const qos: packet.QoS = @fromBackingInt(@intCast(k.ranged(0, 2)));
                const len = k.ranged(0, 7);
                break :blk packet.encodePacket(&buf, v, .{ .publish = .{
                    .topic = multi_topics[k.ranged(0, multi_topics.len - 1)],
                    .payload = "12345678"[0..len],
                    .qos = qos,
                    .retain = k.byte() & 1 == 0,
                    .dup = qos != .at_most_once and k.byte() & 3 == 0,
                    .packet_id = if (qos == .at_most_once) 0 else id,
                } }) catch continue;
            },
            4, 5 => packet.encodePacket(&buf, v, .{ .subscribe = .{ .packet_id = id, .filters = &.{.{
                .filter = multi_filters[k.ranged(0, multi_filters.len - 1)],
                .qos = @fromBackingInt(@intCast(k.ranged(0, 2))),
                .no_local = slot.v5 and k.byte() & 3 == 0,
                .retain_as_published = slot.v5 and k.byte() & 1 == 0,
                .retain_handling = if (slot.v5) @fromBackingInt(@intCast(k.ranged(0, 2))) else .send_on_subscribe,
            }} } }) catch continue,
            6 => packet.encodePacket(&buf, v, .{ .unsubscribe = .{ .packet_id = id, .filters = &.{multi_filters[k.ranged(0, multi_filters.len - 1)]} } }) catch continue,
            7 => packet.encodePacket(&buf, v, .{ .puback = .{ .packet_id = id } }) catch continue,
            8 => packet.encodePacket(&buf, v, .{ .pubrec = .{ .packet_id = id } }) catch continue,
            9 => packet.encodePacket(&buf, v, .{ .pubrel = .{ .packet_id = id } }) catch continue,
            10 => packet.encodePacket(&buf, v, .{ .pubcomp = .{ .packet_id = id } }) catch continue,
            11 => packet.encodePingreq(&buf) catch continue,
            12 => packet.encodePacket(&buf, v, .{ .disconnect = .{} }) catch continue,
            13 => {
                // The peer vanishes without a DISCONNECT.
                broker.remove(conn);
                slot.conn = null;
                continue;
            },
            14 => {
                if (broker.keepAliveExpired(conn, now + k.ranged(0, 20_000))) {
                    broker.remove(conn);
                    slot.conn = null;
                }
                continue;
            },
            else => buf[0..k.ranged(1, 8)], // raw bytes (15, 19)
        };
        try multiStep(&broker, slot, bytes, now);
    }

    if (broker.retainedBytes() > 0) MultiMark.mark(.retained_stored);
    for (multi_ids) |cid| if (broker.sessionQueued(cid)) |q| if (q > 0) {
        MultiMark.mark(.queued_offline);
        break;
    };

    // The caps held, whatever happened.
    if (broker.sessionCount() > max_sessions) return error.SessionCapExceeded;
    if (broker.retainedBytes() > 256) return error.RetainedCapExceeded;
    for (multi_ids) |cid| if (broker.sessionQueued(cid)) |q| if (q > max_queued) return error.QueueCapExceeded;
}

/// Feed `bytes` to the slot's connection and let the broker process them; a
/// connection it closes, or fails, is removed as a server loop would.
fn multiStep(broker: *mqtt.Broker, slot: *MultiSlot, bytes: []const u8, now: i64) !void {
    const conn = slot.conn.?;
    var gone = false;
    broker.feed(conn, bytes) catch {
        gone = true;
    };
    if (!gone) {
        const disp = broker.process(conn, now) catch |e| blk: {
            if (e == error.TransportFailed) MultiMark.mark(.write_failed);
            break :blk mqtt.broker.Disposition.close;
        };
        gone = disp == .close;
    }
    // A write that failed on the way marks the connection disconnected.
    if (conn.state == .disconnected) gone = true;
    if (gone) {
        broker.remove(conn);
        slot.conn = null;
    }
}
