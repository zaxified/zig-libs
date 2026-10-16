// SPDX-License-Identifier: MIT

//! Automatic-reconnect helpers for the sans-I/O `Client`: a backoff
//! `Reconnect` schedule and a `SubscriptionSet` that replays the
//! subscriptions on a new connection.
//!
//! Neither reads a clock, sleeps, spawns or allocates. The caller owns the
//! loop: when the transport dies it calls `Client.connectionLost` and
//! `Reconnect.failed(now, bits)`; once `Reconnect.due(now)` it dials and calls
//! `Client.connect`; on a successful CONNACK it calls `Reconnect.connected()`
//! and, when the server holds no session (`connack.session_present == false`)
//! or the client did not ask to resume, `SubscriptionSet.resubscribe`. A
//! failed dial or a refused CONNACK is another `failed`. In-flight QoS 1/2
//! publishes are resumed by the client's own outbox (`Client.Buffers.outbox`).

const std = @import("std");
const packet = @import("packet.zig");
const topic_rules = @import("topic.zig");
const client_mod = @import("client.zig");

const Client = client_mod.Client;

// ── backoff schedule ────────────────────────────────────────────────────────

/// Exponential backoff with optional full jitter.
pub const Reconnect = struct {
    pub const Jitter = enum { none, full };

    pub const Options = struct {
        /// Delay after the first failure.
        initial_ms: u64 = 1000,
        /// Ceiling of the delay (before jitter).
        max_ms: u64 = 60_000,
        /// Growth per further failure; 0 and 1 mean a constant `initial_ms`.
        multiplier: u32 = 2,
        /// `.full`: the wait is uniform in [0, delay] when random bits are
        /// given to `failed`; `.none`: always the full delay.
        jitter: Jitter = .full,
    };

    options: Options,
    failures: u32 = 0,
    next_at: ?u64 = null,

    pub fn init(options: Options) Reconnect {
        return .{ .options = options };
    }

    /// Record a failed attempt or a lost connection at `now` (ms) and return
    /// when the next attempt is due: `now + delay`, where delay =
    /// min(max_ms, initial_ms * multiplier^(attempts - 1)). With
    /// `jitter = .full` and non-null `random_bits` the wait is instead
    /// uniform in [0, delay] (the high 32 bits of `random_bits` scaled by
    /// delay + 1); null bits mean no jitter. Never overflows: arithmetic
    /// saturates.
    pub fn failed(r: *Reconnect, now: u64, random_bits: ?u64) u64 {
        r.failures +|= 1;
        const o = r.options;
        var delay = o.initial_ms;
        if (o.multiplier > 1) {
            var i: u32 = 1;
            while (i < r.failures and delay > 0 and delay < o.max_ms) : (i += 1) delay *|= o.multiplier;
        }
        delay = @min(delay, o.max_ms);
        var wait = delay;
        if (o.jitter == .full) if (random_bits) |bits| {
            const hi: u128 = bits >> 32;
            wait = @intCast((hi * (@as(u128, delay) + 1)) >> 32);
        };
        const at = now +| wait;
        r.next_at = at;
        return at;
    }

    /// The connection is up: the failure count and the schedule restart.
    pub fn connected(r: *Reconnect) void {
        r.failures = 0;
        r.next_at = null;
    }

    /// Whether an attempt may start at `now`. Before any failure is
    /// recorded (nothing scheduled) it is true: the first attempt is
    /// immediate.
    pub fn due(r: *const Reconnect, now: u64) bool {
        return if (r.next_at) |t| now >= t else true;
    }

    /// When the next attempt is due, or null with nothing scheduled.
    pub fn nextAttemptAt(r: *const Reconnect) ?u64 {
        return r.next_at;
    }

    /// Consecutive failures recorded since the last `connected`.
    pub fn attempts(r: *const Reconnect) u32 {
        return r.failures;
    }
};

// ── subscription replay ─────────────────────────────────────────────────────

/// The filters to re-subscribe after a reconnect, in caller-provided storage
/// (no allocation).
///
/// `storage` holds the filter strings back to back; `slots` holds one `Entry`
/// per filter and so bounds how many there are. Both can run out: `add` then
/// returns `error.SubscriptionSetFull` and changes nothing.
pub const SubscriptionSet = struct {
    /// Filters per SUBSCRIBE packet that `resubscribe` sends.
    pub const max_filters_per_subscribe = 32;

    pub const Error = error{SubscriptionSetFull} || topic_rules.FilterError;

    /// One remembered subscription: where its filter lives plus the
    /// `packet.Subscription` options.
    pub const Entry = struct {
        offset: usize = 0,
        len: usize = 0,
        qos: packet.QoS = .at_most_once,
        no_local: bool = false,
        retain_as_published: bool = false,
        retain_handling: packet.RetainHandling = .send_on_subscribe,
    };

    storage: []u8,
    slots: []Entry,
    count: usize = 0,
    used: usize = 0,

    pub fn init(storage: []u8, slots: []Entry) SubscriptionSet {
        return .{ .storage = storage, .slots = slots };
    }

    pub fn len(s: *const SubscriptionSet) usize {
        return s.count;
    }

    /// Remember `sub` (the filter is copied). An equal filter already in the
    /// set has its options replaced and keeps its place. An invalid filter is
    /// `error.InvalidTopicFilter`.
    pub fn add(s: *SubscriptionSet, sub: packet.Subscription) Error!void {
        try topic_rules.validateFilter(sub.filter);
        if (s.find(sub.filter)) |i| {
            setOptions(&s.slots[i], sub);
            return;
        }
        if (s.count >= s.slots.len or s.used + sub.filter.len > s.storage.len) return error.SubscriptionSetFull;
        @memcpy(s.storage[s.used..][0..sub.filter.len], sub.filter);
        s.slots[s.count] = .{ .offset = s.used, .len = sub.filter.len };
        setOptions(&s.slots[s.count], sub);
        s.count += 1;
        s.used += sub.filter.len;
    }

    /// Forget `filter`; false when it was not in the set.
    pub fn remove(s: *SubscriptionSet, filter: []const u8) bool {
        const i = s.find(filter) orelse return false;
        const e = s.slots[i];
        std.mem.copyForwards(u8, s.storage[e.offset..], s.storage[e.offset + e.len .. s.used]);
        s.used -= e.len;
        for (s.slots[i + 1 .. s.count]) |*o| o.offset -= e.len;
        std.mem.copyForwards(Entry, s.slots[i .. s.count - 1], s.slots[i + 1 .. s.count]);
        s.count -= 1;
        return true;
    }

    /// Send SUBSCRIBE packets for every remembered filter, in the order they
    /// were added, at most `max_filters_per_subscribe` filters per packet.
    /// Returns the number of packets sent (0 for an empty set). The SUBACKs
    /// surface as ordinary `Event.suback`s.
    pub fn resubscribe(s: *const SubscriptionSet, client: *Client, now: u64) client_mod.Error!usize {
        var cursor: usize = 0;
        return s.resubscribeFrom(client, now, &cursor);
    }

    /// `resubscribe` that can be resumed: `cursor` is the index of the first
    /// filter not yet sent (start at 0) and advances after every packet that
    /// went out, also when a later one fails. After an error (typically
    /// `TooManyInFlight`: the client's packet-id pool is full) call again with
    /// the same cursor once acknowledgements have freed ids; the filters
    /// already sent are not repeated. Done when `cursor.* == len()`.
    pub fn resubscribeFrom(s: *const SubscriptionSet, client: *Client, now: u64, cursor: *usize) client_mod.Error!usize {
        var chunk: [max_filters_per_subscribe]packet.Subscription = undefined;
        var sent: usize = 0;
        var i: usize = cursor.*;
        while (i < s.count) {
            const n = @min(max_filters_per_subscribe, s.count - i);
            for (chunk[0..n], s.slots[i..][0..n]) |*dst, e| dst.* = s.toSubscription(e);
            _ = try client.subscribe(now, chunk[0..n]);
            sent += 1;
            i += n;
            cursor.* = i;
        }
        return sent;
    }

    fn toSubscription(s: *const SubscriptionSet, e: Entry) packet.Subscription {
        return .{
            .filter = s.storage[e.offset..][0..e.len],
            .qos = e.qos,
            .no_local = e.no_local,
            .retain_as_published = e.retain_as_published,
            .retain_handling = e.retain_handling,
        };
    }

    fn setOptions(e: *Entry, sub: packet.Subscription) void {
        e.qos = sub.qos;
        e.no_local = sub.no_local;
        e.retain_as_published = sub.retain_as_published;
        e.retain_handling = sub.retain_handling;
    }

    fn find(s: *const SubscriptionSet, filter: []const u8) ?usize {
        for (s.slots[0..s.count], 0..) |e, i| {
            if (std.mem.eql(u8, s.storage[e.offset..][0..e.len], filter)) return i;
        }
        return null;
    }
};
