// SPDX-License-Identifier: MIT

//! A Mosquitto-style MQTT bridge: joins a local `Broker` to a remote broker
//! by mirroring topics according to rules. Sans-I/O like the rest of the
//! module: the caller owns the remote socket and the clock; every call that
//! depends on time takes `now` (ms).
//!
//! Behaviour follows the documented bridge settings of Mosquitto
//! (mosquitto.conf(5) "Bridges": `topic <pattern> [in|out|both] [qos]
//! [local prefix] [remote prefix]`, `cleansession`, `notifications`,
//! `notification_topic`, `bridge_protocol_version`, `restart_timeout`),
//! written from the documentation only.
//!
//! ## Shape
//!
//! The bridge is two `Client`s:
//!
//! - a *local* client, v5, connected to the local broker through an
//!   in-memory loopback (`Broker.accept` + `feed` + `process`, no socket). It
//!   subscribes to the `out`/`both` rules and is the publisher for `in`
//!   rules. Being an ordinary connection, it sees retained messages and
//!   messages published with `Broker.publish`, and the broker's ACL applies
//!   to it. (Rejected alternative: the `Config.onPublishFn` tap. It does not
//!   see `Broker.publish`, needs the host to wire it, and cannot deliver
//!   retained messages at start-up.)
//! - a *remote* client, v3.1.1 or v5 (`Config.version`), whose bytes go out
//!   through the `Transport` given to `init` and come in through
//!   `remoteBytes`.
//!
//! ## Driving it
//!
//! ```text
//! bridge.init(&local_broker, config, buffers, remote_transport)
//! bridge.start(now)                       // connects + subscribes locally
//! loop:
//!   if bridge.wantConnect(now): dial; ok -> bridge.remoteOpened(now)
//!                                     fail -> bridge.connectionLost(now, bits)
//!   bytes read from the remote socket -> bridge.remoteBytes(bytes)
//!   anything published on the local broker -> (nothing to do)
//!   status = bridge.poll(now)           // pumps both directions
//!   status == .remote_lost -> close the socket, bridge.connectionLost(now, bits)
//! ```
//!
//! `poll` must be called after the local broker delivered something (it is
//! what moves local messages to the remote) and after `remoteBytes`.
//!
//! ## Rules
//!
//! A rule's local filter is `local_prefix ++ pattern`, its remote filter
//! `remote_prefix ++ pattern`. A message on a local topic matching a rule's
//! local filter goes to the remote with `local_prefix` replaced by
//! `remote_prefix`, and the other way round for the remote. The first rule
//! (in order) whose direction allows it and whose filter matches decides.
//! Forwarded messages carry min(message QoS, rule QoS). With a 5.0 remote the
//! forwardable 5.0 properties (Payload Format, Message Expiry, Content Type,
//! Response Topic, Correlation Data, User Properties) travel both ways; a
//! 3.1.1 remote has none. RETAIN is kept on the local side and, from a 5.0 remote
//! (Retain As Published), on live remote messages; a 3.1.1 remote clears it on
//! live deliveries, as it does for Mosquitto bridges (retained messages sent
//! at subscribe time keep it).
//!
//! ## Loops (`both`)
//!
//! Locally the bridge subscribes with 5.0 No Local, so the broker never
//! returns a message the bridge's own connection published. Remotely, a 5.0
//! `version` does the same. With a 3.1.1 remote there is no such flag, so the
//! bridge remembers a hash of the last 32 messages it forwarded out on
//! `both` rules and drops the first incoming remote message that equals one
//! (a heuristic: two byte-identical messages from other publishers arriving
//! at the same moment may lose one). A `both` rule needs distinct
//! `local_prefix` and `remote_prefix` or a 5.0 remote: `init` refuses a
//! `both` rule with equal prefixes over 3.1.1 (`error.LoopProneRule`), the
//! case where a forwarded message would be indistinguishable from a new one.
//!
//! ## Reconnect, in-flight, notifications
//!
//! `connectionLost` schedules the next attempt with `Reconnect` (backoff and
//! jitter) and `wantConnect` reports when it is due. With
//! `Config.clean_session = false` and `Buffers.remote_outbox` set, QoS 1/2
//! messages not yet acknowledged by the remote are resent after a reconnect
//! (see `Client.Buffers.outbox`); with a clean session or when the remote
//! reports no session the remote subscriptions are re-sent (`SubscriptionSet`).
//! Local messages that arrive while the remote link is down are queued in
//! `Buffers.queue` / `queue_entries` (FIFO; QoS 1/2 only unless
//! `Config.queue_qos0`, like Mosquitto's `queue_qos0_messages`) and sent in
//! order after the next CONNACK, once the subscriptions are replayed. When
//! the queue is full the OLDEST entries are dropped to make room (counted in
//! `stats().dropped`, as are messages that cannot be queued at all: QoS 0
//! without the option, no queue storage, larger than the queue). A queue that
//! cannot drain (remote Receive Maximum) keeps order: later messages queue
//! behind it.
//! `Config.notification_topic` gets a retained "1" (on the local broker and
//! on the remote) when the link is up and a retained "0" locally when it is
//! lost; the remote has the Will "0" on the same topic.

const std = @import("std");
const packet = @import("packet.zig");
const topic_rules = @import("topic.zig");
const client_mod = @import("client.zig");
const broker_mod = @import("broker.zig");
const reconnect_mod = @import("reconnect.zig");

const Client = client_mod.Client;
const Broker = broker_mod.Broker;

pub const Direction = enum { in, out, both };

/// One `topic` line of a Mosquitto bridge configuration.
pub const Rule = struct {
    /// A topic filter (`+`, `#` allowed), without prefix.
    pattern: []const u8,
    direction: Direction = .out,
    /// Subscription QoS and the ceiling for forwarded messages.
    qos: packet.QoS = .at_most_once,
    /// Literal prefixes (no wildcards) put before `pattern` on each side.
    local_prefix: []const u8 = "",
    remote_prefix: []const u8 = "",
};

pub const Config = struct {
    rules: []const Rule,
    /// Client id used on the remote broker.
    remote_client_id: []const u8,
    /// Client id of the in-memory connection on the local broker.
    local_client_id: []const u8 = "bridge-local",
    /// Mosquitto `cleansession`; false keeps the remote session (and the
    /// in-flight outbox) across reconnects.
    clean_session: bool = false,
    /// Mosquitto `bridge_protocol_version`.
    version: packet.Version = .v3_1_1,
    keep_alive_s: u16 = 60,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    /// Mosquitto `notifications` + `notification_topic`; null = off.
    notification_topic: ?[]const u8 = null,
    /// Also queue QoS 0 messages while the remote is down (Mosquitto
    /// `queue_qos0_messages`, default off).
    queue_qos0: bool = false,
    /// Give up on a CONNECT that no CONNACK answers after this long: `poll`
    /// then says `.remote_lost` (the caller closes the socket and calls
    /// `connectionLost`, which backs off).
    connack_timeout_ms: u64 = 30_000,
    /// 5.0 remote with `clean_session = false`: the Session Expiry Interval
    /// sent in CONNECT, so the remote really keeps the session (a 5.0 session
    /// otherwise ends at disconnect). Default: never expires.
    session_expiry_s: u32 = 0xFFFFFFFF,
    /// Mosquitto `restart_timeout` is `reconnect.initial_ms` / `max_ms`.
    reconnect: reconnect_mod.Reconnect.Options = .{},
};

/// Caller-provided storage; nothing here is allocated by the bridge. Sizes:
/// the four packet buffers must hold the largest message that is forwarded
/// (plus a few bytes of header), the pipes a burst between two `poll`s.
pub const Buffers = struct {
    local_rx: []u8,
    local_tx: []u8,
    /// Bytes the local client sent to the broker, until `poll` hands them over.
    pipe_up: []u8,
    /// Bytes the local broker delivered to the bridge, until `poll` reads them.
    pipe_down: []u8,
    remote_rx: []u8,
    remote_tx: []u8,
    /// Resume outbox for the remote client; empty = no in-flight resume.
    remote_outbox: []u8 = &.{},
    /// Message queue for a down remote link (bytes; empty = no queue). Each
    /// entry holds the encoded message (topic, payload, properties, ~10 bytes).
    queue: []u8 = &.{},
    /// Bound on the number of queued messages (empty = no queue).
    queue_entries: []QueueEntry = &.{},
    /// Storage for the remote filters replayed after a reconnect.
    sub_storage: []u8,
    sub_slots: []reconnect_mod.SubscriptionSet.Entry,
};

pub const QueueEntry = struct {
    offset: usize = 0,
    len: usize = 0,
    /// Sent on a `both` rule: remembered for 3.1.1 echo suppression.
    both: bool = false,
};

pub const Status = enum {
    ok,
    /// The remote link failed (transport, keep-alive, protocol, refused
    /// CONNECT): close the socket and call `connectionLost`.
    remote_lost,
};

pub const Stats = struct {
    forwarded_out: u64 = 0,
    forwarded_in: u64 = 0,
    /// Messages not forwarded: link down, buffer full, topic too long.
    dropped: u64 = 0,
    echoes_suppressed: u64 = 0,
};

pub const Error = client_mod.Error || broker_mod.Error || reconnect_mod.SubscriptionSet.Error || error{
    /// `start` has not been called, or the local connection is gone.
    NotStarted,
    /// The broker closed the bridge's local connection.
    LocalClosed,
    /// A `both` rule over a 3.1.1 remote with equal local and remote prefix.
    LoopProneRule,
    /// A rule prefix contains a wildcard, or a prefixed filter is too long.
    InvalidRule,
};

const Pipe = struct {
    buf: []u8,
    len: usize = 0,

    fn append(p: *Pipe, bytes: []const u8) bool {
        if (p.len + bytes.len > p.buf.len) return false;
        @memcpy(p.buf[p.len..][0..bytes.len], bytes);
        p.len += bytes.len;
        return true;
    }

    fn clientWrite(ctx: *anyopaque, bytes: []const u8) client_mod.TransportError!void {
        const p: *Pipe = @ptrCast(@alignCast(ctx));
        if (!p.append(bytes)) return error.TransportFailed;
    }

    fn brokerWrite(ctx: *anyopaque, bytes: []const u8) broker_mod.TransportError!void {
        const p: *Pipe = @ptrCast(@alignCast(ctx));
        if (!p.append(bytes)) return error.TransportFailed;
    }
};

const echo_slots = 32;
const topic_buf_len = 1024;

pub const Bridge = struct {
    local: *Broker,
    config: Config,
    conn: ?*broker_mod.Connection = null,
    local_client: Client,
    remote_client: Client,
    up: Pipe,
    down: Pipe,
    subs: reconnect_mod.SubscriptionSet,
    schedule: reconnect_mod.Reconnect,
    remote: enum { down, connecting, up } = .down,
    remote_failed: bool = false,
    connecting_since: u64 = 0,
    /// After a CONNACK: index of the next remote filter to subscribe, and
    /// whether the "1" notification is still owed to the remote. Both wait for
    /// quota (acknowledgements) instead of failing the link.
    resub_cursor: ?usize = null,
    notify_pending: bool = false,
    counters: Stats = .{},
    queue: []u8,
    qentries: []QueueEntry,
    qn: usize = 0,
    qused: usize = 0,
    echo: [echo_slots]u64 = @splat(0),
    echo_next: usize = 0,

    /// Initialize in place (the pipes hand out pointers into `b`, so it must
    /// not move afterwards). Registers the remote filters of the `in` / `both`
    /// rules for replay. `remote` is the write seam of the remote socket.
    // secret-api-ok: `config` (with the remote password) is stored by reference -- its slices point at caller storage; no secret bytes are copied or derived here.
    pub fn init(b: *Bridge, local: *Broker, config: Config, buffers: Buffers, remote: client_mod.Transport) Error!void {
        for (config.rules) |r| {
            if (std.mem.findAny(u8, r.local_prefix, "+#") != null or std.mem.findAny(u8, r.remote_prefix, "+#") != null) return error.InvalidRule;
            topic_rules.validateFilter(r.pattern) catch return error.InvalidRule;
            if (r.local_prefix.len + r.pattern.len > topic_buf_len or r.remote_prefix.len + r.pattern.len > topic_buf_len) return error.InvalidRule;
            if (r.direction == .both and config.version == .v3_1_1 and std.mem.eql(u8, r.local_prefix, r.remote_prefix)) return error.LoopProneRule;
        }
        b.* = .{
            .local = local,
            .config = config,
            .local_client = undefined,
            .remote_client = Client.init(remote, .{ .rx = buffers.remote_rx, .tx = buffers.remote_tx, .outbox = buffers.remote_outbox }),
            .up = .{ .buf = buffers.pipe_up },
            .down = .{ .buf = buffers.pipe_down },
            .subs = reconnect_mod.SubscriptionSet.init(buffers.sub_storage, buffers.sub_slots),
            .schedule = reconnect_mod.Reconnect.init(config.reconnect),
            .queue = buffers.queue,
            .qentries = buffers.queue_entries,
        };
        b.local_client = Client.init(.{ .ctx = &b.up, .writeFn = Pipe.clientWrite }, .{ .rx = buffers.local_rx, .tx = buffers.local_tx });
        const v5 = config.version == .v5;
        for (config.rules) |r| {
            if (r.direction == .out) continue;
            var buf: [topic_buf_len]u8 = undefined;
            const filter = try join(&buf, r.remote_prefix, r.pattern);
            try b.subs.add(.{ .filter = filter, .qos = r.qos, .no_local = v5, .retain_as_published = v5 });
        }
    }

    /// Release the local connection (the broker keeps no state for it: the
    /// bridge connects with a clean session).
    pub fn deinit(b: *Bridge) void {
        if (b.conn) |c| b.local.remove(c);
        b.conn = null;
    }

    /// Connect the local client to the local broker, subscribe it to the
    /// `out` / `both` rules and publish the initial "0" notification.
    pub fn start(b: *Bridge, now: u64) Error!void {
        const transport = broker_mod.Transport{ .ctx = &b.down, .writeFn = Pipe.brokerWrite };
        b.conn = try b.local.accept(transport);
        try b.local_client.connect(now, .{
            .client_id = b.config.local_client_id,
            .clean_session = true,
            .version = .v5,
        });
        try b.pumpLocal(now);
        if (b.local_client.state != .connected) return error.LocalClosed;
        for (b.config.rules) |r| {
            if (r.direction == .in) continue;
            var buf: [topic_buf_len]u8 = undefined;
            const filter = try join(&buf, r.local_prefix, r.pattern);
            _ = try b.local_client.subscribe(now, &.{.{ .filter = filter, .qos = r.qos, .no_local = true, .retain_as_published = true }});
            try b.pumpLocal(now);
        }
        if (b.config.notification_topic) |t| try b.local.publishWith(t, "0", .{ .qos = .at_least_once, .retain = true });
    }

    /// Messages waiting for the remote link.
    pub fn queued(b: *const Bridge) usize {
        return b.qn;
    }

    pub fn stats(b: *const Bridge) Stats {
        return b.counters;
    }

    /// True while the remote link is established (CONNACK accepted).
    pub fn remoteUp(b: *const Bridge) bool {
        return b.remote == .up;
    }

    /// Should the caller dial the remote now?
    pub fn wantConnect(b: *const Bridge, now: u64) bool {
        return b.remote == .down and b.schedule.due(now);
    }

    /// When the next dial is due (null = now).
    pub fn nextAttemptAt(b: *const Bridge) ?u64 {
        return b.schedule.nextAttemptAt();
    }

    /// The caller's dial succeeded: send CONNECT (with the notification Will).
    // secret-api-ok: the remote password reaches only `Client.connect`, whose `packet.encodeConnect` runs under the credential burn that covers every frame copying it (stackprobe_test.zig); nothing here holds a copy.
    pub fn remoteOpened(b: *Bridge, now: u64) Error!void {
        const will: ?packet.Will = if (b.config.notification_topic) |t|
            .{ .topic = t, .message = "0", .qos = .at_least_once, .retain = true }
        else
            null;
        b.remote_failed = false;
        try b.remote_client.connect(now, .{
            .client_id = b.config.remote_client_id,
            .clean_session = b.config.clean_session,
            .keep_alive_s = b.config.keep_alive_s,
            .username = b.config.username,
            .password = b.config.password,
            .version = b.config.version,
            .will = will,
            .properties = if (b.config.version == .v5 and !b.config.clean_session)
                .{ .session_expiry_interval = b.config.session_expiry_s }
            else
                .{},
        });
        b.remote = .connecting;
        b.connecting_since = now;
    }

    /// Bytes read from the remote socket. Call `poll` afterwards. Feeds at
    /// most `Client.rxRoom`; returns `error.RxBufferFull` when the remote
    /// outpaces `poll` (poll more often, or feed in smaller pieces).
    pub fn remoteBytes(b: *Bridge, bytes: []const u8) Error!void {
        try b.remote_client.feed(bytes);
    }

    /// The remote link ended (dial failed, socket closed, or `poll` said
    /// `.remote_lost`). Schedules the next attempt and returns its time. The
    /// local notification becomes "0".
    // secret-api-ok: the remote credentials in `config` are not read here; this only resets link state and schedules a retry.
    pub fn connectionLost(b: *Bridge, now: u64, random_bits: ?u64) u64 {
        const was_up = b.remote == .up;
        b.remote_client.connectionLost();
        b.remote = .down;
        b.remote_failed = false;
        b.resub_cursor = null;
        b.notify_pending = false;
        if (was_up) if (b.config.notification_topic) |t| {
            b.local.publishWith(t, "0", .{ .qos = .at_least_once, .retain = true }) catch {};
        };
        return b.schedule.failed(now, random_bits);
    }

    /// Move everything that is pending: local messages to the remote, remote
    /// messages to the local broker, remote handshake and keep-alive.
    pub fn poll(b: *Bridge, now: u64) Error!Status {
        try b.pumpLocal(now);
        if (b.remote != .down) {
            b.remoteEvents(now);
            b.remote_client.tick(now) catch {
                b.remote_failed = true;
            };
            if (b.remote == .connecting and now >= b.connecting_since +| b.config.connack_timeout_ms) b.remote_failed = true;
            b.stepPending(now);
        }
        try b.pumpLocal(now);
        return if (b.remote_failed) .remote_lost else .ok;
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn remoteEvents(b: *Bridge, now: u64) void {
        while (true) {
            const ev = b.remote_client.poll(now) catch {
                b.remote_failed = true;
                return;
            } orelse return;
            b.remoteEvent(now, ev) catch {
                b.remote_failed = true;
                return;
            };
            if (b.remote_failed) return;
        }
    }

    fn remoteEvent(b: *Bridge, now: u64, ev: client_mod.Event) Error!void {
        switch (ev) {
            .connack => |ca| {
                const ok = if (b.config.version == .v5) ca.reason_code == .success else ca.return_code == .accepted;
                if (!ok) {
                    b.remote_failed = true;
                    return;
                }
                b.remote = .up;
                b.schedule.connected();
                b.resub_cursor = if (!ca.session_present or b.config.clean_session) 0 else null;
                if (b.config.notification_topic) |t| {
                    b.notify_pending = true;
                    b.local.publishWith(t, "1", .{ .qos = .at_least_once, .retain = true }) catch {};
                }
                b.stepPending(now);
            },
            .message => |m| b.forwardIn(now, m),
            .disconnect => b.remote_failed = true,
            else => {},
        }
    }

    fn isQuota(e: anyerror) bool {
        return e == error.TooManyInFlight or e == error.ReceiveMaximumReached or e == error.OutboxFull;
    }

    /// What the remote link still owes after a CONNACK, in order: the
    /// subscriptions, the "1" notification, the queued messages. Each step
    /// that runs out of quota (the resumed outbox may fill the window or the
    /// packet-id pool) waits for the next acknowledgement; only a real
    /// failure fails the link.
    fn stepPending(b: *Bridge, now: u64) void {
        if (b.remote != .up) return;
        if (b.resub_cursor) |*cur| {
            _ = b.subs.resubscribeFrom(&b.remote_client, now, cur) catch |e| {
                if (!isQuota(e)) b.remote_failed = true;
                return;
            };
            b.resub_cursor = null;
        }
        if (b.notify_pending) if (b.config.notification_topic) |t| {
            _ = b.remote_client.publish(now, t, "1", .{ .qos = .at_least_once, .retain = true }) catch |e| {
                if (!isQuota(e)) b.remote_failed = true;
                return;
            };
            b.notify_pending = false;
        };
        b.drainQueue(now);
    }

    /// Local client <-> local broker, until nothing moves.
    fn pumpLocal(b: *Bridge, now: u64) Error!void {
        const conn = b.conn orelse return error.NotStarted;
        var rounds: usize = 0;
        while (rounds < 32) : (rounds += 1) {
            var moved = false;
            if (b.up.len > 0) {
                try b.local.feed(conn, b.up.buf[0..b.up.len]);
                b.up.len = 0;
                moved = true;
                if (try b.local.process(conn, @intCast(now)) == .close) return error.LocalClosed;
            }
            if (b.down.len > 0) {
                const n = @min(b.down.len, b.local_client.rxRoom());
                if (n > 0) {
                    try b.local_client.feed(b.down.buf[0..n]);
                    std.mem.copyForwards(u8, b.down.buf[0..], b.down.buf[n..b.down.len]);
                    b.down.len -= n;
                    moved = true;
                }
            }
            while (try b.local_client.poll(now)) |ev| {
                moved = true;
                switch (ev) {
                    .message => |m| b.forwardOut(now, m),
                    else => {},
                }
            }
            if (!moved) break;
        }
    }

    fn minQos(a: packet.QoS, c: packet.QoS) packet.QoS {
        return if (@backingInt(a) < @backingInt(c)) a else c;
    }

    fn join(buf: []u8, a: []const u8, c: []const u8) Error![]const u8 {
        if (a.len + c.len > buf.len) return error.InvalidRule;
        @memcpy(buf[0..a.len], a);
        @memcpy(buf[a.len..][0..c.len], c);
        return buf[0 .. a.len + c.len];
    }

    fn hashMessage(topic_name: []const u8, payload: []const u8) u64 {
        var h = std.hash.Wyhash.init(0x6272696467650001);
        h.update(topic_name);
        h.update(&.{0});
        h.update(payload);
        const v = h.final();
        return if (v == 0) 1 else v;
    }

    /// A message the local broker delivered: send it to the remote.
    fn forwardOut(b: *Bridge, now: u64, m: client_mod.Message) void {
        for (b.config.rules) |r| {
            if (r.direction == .in) continue;
            var fbuf: [topic_buf_len]u8 = undefined;
            const filter = join(&fbuf, r.local_prefix, r.pattern) catch continue;
            if (!topic_rules.matches(filter, m.topic)) continue;
            if (!std.mem.startsWith(u8, m.topic, r.local_prefix)) continue;
            var tbuf: [topic_buf_len]u8 = undefined;
            const remote_topic = join(&tbuf, r.remote_prefix, m.topic[r.local_prefix.len..]) catch {
                b.counters.dropped += 1;
                return;
            };
            if (remote_topic.len > 0 and remote_topic[0] == '$' and m.topic[0] != '$') {
                b.counters.dropped += 1; // a prefix must not turn a topic into a `$` one
                return;
            }
            const qos = minQos(m.qos, r.qos);
            var rt_buf: [topic_buf_len]u8 = undefined;
            const props = if (b.config.version == .v5) mapProps(m.properties, r.local_prefix, r.remote_prefix, &rt_buf) else packet.Properties{};
            const both = r.direction == .both;
            if (b.remote != .up or b.qn > 0) {
                if (b.queue.len > 0 and (qos != .at_most_once or b.config.queue_qos0)) {
                    b.enqueue(remote_topic, m.payload, qos, m.retain, props, both);
                } else if (b.remote == .up) {
                    b.sendRemote(now, remote_topic, m.payload, qos, m.retain, props, both);
                } else {
                    b.counters.dropped += 1;
                }
                return;
            }
            b.sendRemote(now, remote_topic, m.payload, qos, m.retain, props, both);
            return;
        }
    }

    fn sendRemote(b: *Bridge, now: u64, remote_topic: []const u8, payload: []const u8, qos: packet.QoS, retain: bool, props: packet.Properties, both: bool) void {
        _ = b.remote_client.publish(now, remote_topic, payload, .{ .qos = qos, .retain = retain, .properties = props }) catch |e| {
            // The remote's window (or our outbox / id pool) is full: wait in
            // the queue rather than lose a message the broker already considers
            // delivered to us.
            if (isQuota(e) and b.queue.len > 0 and (qos != .at_most_once or b.config.queue_qos0)) {
                b.enqueue(remote_topic, payload, qos, retain, props, both);
            } else {
                if (e == error.TransportFailed) b.remote_failed = true;
                b.counters.dropped += 1;
            }
            return;
        };
        b.noteSent(remote_topic, payload, both);
    }

    fn noteSent(b: *Bridge, remote_topic: []const u8, payload: []const u8, both: bool) void {
        if (both and b.config.version == .v3_1_1) {
            b.echo[b.echo_next] = hashMessage(remote_topic, payload);
            b.echo_next = (b.echo_next + 1) % echo_slots;
        }
        b.counters.forwarded_out += 1;
    }

    /// The forwardable properties, with the Response Topic carried through the
    /// same prefix rewrite as the topic, or dropped when it lies outside the
    /// rule's prefix: a remote must not choose where local replies go, nor
    /// learn local topic names. Correlation Data is opaque and passes.
    fn mapProps(p: packet.Properties, from: []const u8, to: []const u8, buf: []u8) packet.Properties {
        var o = forwardProps(p);
        if (p.response_topic) |rt| {
            o.response_topic = if (std.mem.startsWith(u8, rt, from)) (join(buf, to, rt[from.len..]) catch null) else null;
            if (o.response_topic) |mapped| if (mapped.len == 0 or (mapped[0] == '$' and rt[0] != '$')) {
                o.response_topic = null;
            };
        }
        return o;
    }

    fn forwardProps(p: packet.Properties) packet.Properties {
        return .{
            .payload_format = p.payload_format,
            .message_expiry_interval = p.message_expiry_interval,
            .content_type = p.content_type,
            .response_topic = p.response_topic,
            .correlation_data = p.correlation_data,
            .user_properties = p.user_properties,
        };
    }

    /// Queue a message (as an encoded 5.0 PUBLISH), dropping the oldest ones
    /// until it fits.
    fn enqueue(b: *Bridge, remote_topic: []const u8, payload: []const u8, qos: packet.QoS, retain: bool, props: packet.Properties, both: bool) void {
        const p = packet.Publish{
            .topic = remote_topic,
            .payload = payload,
            .qos = qos,
            .retain = retain,
            .packet_id = if (qos == .at_most_once) 0 else 1,
            .properties = props,
        };
        const need = packet.packetWireLen(.v5, .{ .publish = p }) catch {
            b.counters.dropped += 1;
            return;
        };
        if (need > b.queue.len or b.qentries.len == 0) {
            b.counters.dropped += 1;
            return;
        }
        while (b.qn > 0 and (b.qn >= b.qentries.len or b.qused + need > b.queue.len)) {
            b.queuePop();
            b.counters.dropped += 1;
        }
        const bytes = packet.encodePacket(b.queue[b.qused..], .v5, .{ .publish = p }) catch {
            b.counters.dropped += 1;
            return;
        };
        b.qentries[b.qn] = .{ .offset = b.qused, .len = bytes.len, .both = both };
        b.qn += 1;
        b.qused += bytes.len;
    }

    fn queuePop(b: *Bridge) void {
        const e = b.qentries[0];
        std.mem.copyForwards(u8, b.queue[0..], b.queue[e.len..b.qused]);
        b.qused -= e.len;
        for (b.qentries[1..b.qn]) |*x| x.offset -= e.len;
        std.mem.copyForwards(QueueEntry, b.qentries[0 .. b.qn - 1], b.qentries[1..b.qn]);
        b.qn -= 1;
    }

    /// Send queued messages in order while the remote link is up; stops
    /// (keeping the rest) when the remote's window is full.
    fn drainQueue(b: *Bridge, now: u64) void {
        while (b.qn > 0 and b.remote == .up) {
            const e = b.qentries[0];
            const dec = (packet.decodePacket(b.queue[e.offset..][0..e.len], .v5) catch null) orelse {
                b.queuePop();
                b.counters.dropped += 1;
                continue;
            };
            const p = dec.packet.publish;
            const props = if (b.config.version == .v5) p.properties else packet.Properties{};
            _ = b.remote_client.publish(now, p.topic, p.payload, .{ .qos = p.qos, .retain = p.retain, .properties = props }) catch |err| switch (err) {
                error.ReceiveMaximumReached, error.TooManyInFlight, error.OutboxFull => return,
                error.NotConnected, error.TransportFailed => {
                    b.remote_failed = true;
                    return;
                },
                else => {
                    b.queuePop();
                    b.counters.dropped += 1;
                    continue;
                },
            };
            b.noteSent(p.topic, p.payload, e.both);
            b.queuePop();
        }
    }

    /// A message from the remote: publish it on the local broker.
    fn forwardIn(b: *Bridge, now: u64, m: client_mod.Message) void {
        for (b.config.rules) |r| {
            if (r.direction == .out) continue;
            var fbuf: [topic_buf_len]u8 = undefined;
            const filter = join(&fbuf, r.remote_prefix, r.pattern) catch continue;
            if (!topic_rules.matches(filter, m.topic)) continue;
            if (!std.mem.startsWith(u8, m.topic, r.remote_prefix)) continue;
            if (r.direction == .both and b.config.version == .v3_1_1) {
                const h = hashMessage(m.topic, m.payload);
                for (&b.echo) |*e| if (e.* == h) {
                    e.* = 0;
                    b.counters.echoes_suppressed += 1;
                    return;
                };
            }
            var tbuf: [topic_buf_len]u8 = undefined;
            const local_topic = join(&tbuf, r.local_prefix, m.topic[r.remote_prefix.len..]) catch {
                b.counters.dropped += 1;
                return;
            };
            if (local_topic.len > 0 and local_topic[0] == '$' and m.topic[0] != '$') {
                b.counters.dropped += 1; // a prefix must not turn a topic into a `$` one
                return;
            }
            var rt_buf: [topic_buf_len]u8 = undefined;
            const opts: Client.PublishOptions = .{ .qos = minQos(m.qos, r.qos), .retain = m.retain, .properties = mapProps(m.properties, r.remote_prefix, r.local_prefix, &rt_buf) };
            _ = b.local_client.publish(now, local_topic, m.payload, opts) catch |e| switch (e) {
                // too many unacknowledged: let the broker answer, then retry once
                error.TooManyInFlight, error.ReceiveMaximumReached => {
                    b.pumpLocal(now) catch {};
                    _ = b.local_client.publish(now, local_topic, m.payload, opts) catch {
                        b.counters.dropped += 1;
                        return;
                    };
                },
                else => {
                    b.counters.dropped += 1;
                    return;
                },
            };
            b.counters.forwarded_in += 1;
            return;
        }
    }
};
