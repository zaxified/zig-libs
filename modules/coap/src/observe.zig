// SPDX-License-Identifier: MIT

//! coap Observe (C7) — RFC 7641: a client registers interest in a resource with
//! an **Observe** option (number 6, value 0 = register) on a GET; the server
//! then pushes a **notification** — a fresh response carrying the current
//! representation and an Observe option holding a monotonically increasing 24-bit
//! sequence number — every time the resource changes, until the client
//! deregisters (Observe value 1) or the server drops the subscription.
//!
//! Two caller-driven, zero-allocation pieces, in the same style as the rest of
//! the module:
//!
//! - **`Registry`** — the server's subscription table over caller storage
//!   (`[]Entry`), structurally like `reliability.Dedup`: a bounded array keyed by
//!   `(token, resource)` with FIFO eviction when full. `notify` applies the RFC
//!   7641 §4.4 freshness test so an out-of-order/replayed notification is
//!   rejected.
//! - **`Sequence`** — the monotonic 24-bit generator for the notification
//!   sequence numbers, plus `isNewer`, the RFC 1982-style "lollipop" comparison.
//!
//! **Server push reuses `server.Server.separate` unchanged**: a notification is
//! just a separate response (echoing the observed request's token) with an
//! Observe option added — no fresh request is involved. Build the option value
//! with `encodeValue(seq)` and put option `options.number.observe` on the
//! response; sort the options ascending as usual.
//!
//! **Reliability interaction (caller glue, no change to `reliability.zig`).** A
//! CON notification is driven by a `reliability.Retransmit` like any other CON.
//! If it exhausts retransmission (`.timed_out`) or the peer answers with a Reset,
//! the subscription is dead: the caller calls `Registry.cancel(token, resource)`.
//! (An RST correlates by message id, so the caller maps the notification's id
//! back to its `(token, resource)` — a few lines in its own loop.)

const std = @import("std");
const coap = @import("root.zig");

/// The Observe sequence number space is 24-bit (RFC 7641 §2).
pub const max_sequence: u24 = std.math.maxInt(u24);

/// Observe option values used in a *request* (RFC 7641 §2). In a *response* the
/// value is instead the notification sequence number.
pub const request = struct {
    /// Register — start observing.
    pub const register: u24 = 0;
    /// Deregister — stop observing.
    pub const deregister: u24 = 1;
};

/// The monotonic 24-bit sequence generator a server stamps onto notifications.
/// `next()` returns the current value and advances (wrapping at 2^24); the
/// wrap-around is handled by `isNewer` on the receiving side.
pub const Sequence = struct {
    value: u24 = 0,

    pub fn next(self: *Sequence) u24 {
        const v = self.value;
        self.value +%= 1;
        return v;
    }
};

/// RFC 7641 §4.4 freshness ("lollipop" / RFC 1982 serial-number arithmetic):
/// is a notification with sequence `new` newer than the last-seen `old`? True
/// when `new` is ahead within half the 24-bit space (directly, or across the
/// wrap). A stale or reordered notification is therefore rejected.
pub fn isNewer(old: u24, new: u24) bool {
    const half: u24 = 1 << 23;
    return (old < new and new - old < half) or (old > new and old - new > half);
}

/// Encode an Observe sequence as its option value: a 0..3-byte minimal
/// big-endian uint (0 → empty), like the CoAP uint format (RFC 7641 §2 uses the
/// §3.2 uint representation).
pub fn encodeValue(seq: u24, buf: *[3]u8) []const u8 {
    buf.* = .{ @truncate(seq >> 16), @truncate(seq >> 8), @truncate(seq) };
    var start: usize = 0;
    while (start < 3 and buf[start] == 0) start += 1;
    return buf[start..];
}

/// Decode an Observe option value (0..3 bytes) back to a sequence number.
pub fn decodeValue(bytes: []const u8) u24 {
    const tail = if (bytes.len > 3) bytes[bytes.len - 3 ..] else bytes;
    var v: u32 = 0;
    for (tail) |b| v = (v << 8) | b;
    return @truncate(v);
}

/// A server-side table of active observations over caller storage — a bounded
/// array of `(token, resource) → last sequence` entries with FIFO eviction when
/// full, the same zero-allocation pattern as `reliability.Dedup`. The `resource`
/// key is a caller-chosen identifier (e.g. a hash of the Uri-Path) so the table
/// stays fixed-size.
pub const Registry = struct {
    entries: []Entry,
    len: usize = 0,

    pub const Entry = struct {
        token_buf: [coap.max_token_len]u8 = undefined,
        token_len: u8 = 0,
        resource: u64 = 0,
        /// The sequence number stamped on the last notification for this entry.
        last_seq: u24 = 0,

        pub fn token(e: *const Entry) []const u8 {
            return e.token_buf[0..e.token_len];
        }
    };

    /// The result of feeding an arriving notification's sequence to `notify`.
    pub const Update = enum {
        /// Fresh — newer than the last seen; `last_seq` advanced.
        accepted,
        /// Stale or out-of-order — rejected (RFC 7641 §4.4); `last_seq` unchanged.
        stale,
    };

    /// Initialize over caller storage.
    pub fn init(storage: []Entry) Registry {
        return .{ .entries = storage };
    }

    fn find(self: *Registry, tok: []const u8, resource: u64) ?*Entry {
        for (self.entries[0..self.len]) |*e| {
            if (e.resource == resource and std.mem.eql(u8, e.token(), tok)) return e;
        }
        return null;
    }

    /// Register (or refresh) a subscription for `(tok, resource)` with the
    /// initial notification's `seq`. On a full registry the oldest entry is
    /// evicted (FIFO). Returns the live entry.
    pub fn register(self: *Registry, tok: []const u8, resource: u64, seq: u24) *Entry {
        if (self.find(tok, resource)) |e| {
            e.last_seq = seq;
            return e;
        }
        const slot = if (self.len < self.entries.len) blk: {
            const e = &self.entries[self.len];
            self.len += 1;
            break :blk e;
        } else blk: {
            // Full: evict the oldest (index 0), shift the rest down.
            std.mem.copyForwards(Entry, self.entries[0 .. self.len - 1], self.entries[1..self.len]);
            break :blk &self.entries[self.len - 1];
        };
        slot.* = .{};
        slot.token_len = @intCast(@min(tok.len, coap.max_token_len));
        @memcpy(slot.token_buf[0..slot.token_len], tok[0..slot.token_len]);
        slot.resource = resource;
        slot.last_seq = seq;
        return slot;
    }

    /// A notification carrying `seq` arrived for `(tok, resource)`. Returns null
    /// when there is no such subscription, else whether it is fresh (`accepted`,
    /// `last_seq` advanced) or stale/out-of-order (`stale`, rejected).
    pub fn notify(self: *Registry, tok: []const u8, resource: u64, seq: u24) ?Update {
        const e = self.find(tok, resource) orelse return null;
        if (isNewer(e.last_seq, seq)) {
            e.last_seq = seq;
            return .accepted;
        }
        return .stale;
    }

    /// Cancel a subscription — a client Observe:1 (deregister) GET, or a
    /// RST/timeout on a CON notification. Returns whether an entry was removed.
    pub fn cancel(self: *Registry, tok: []const u8, resource: u64) bool {
        for (self.entries[0..self.len], 0..) |*e, i| {
            if (e.resource == resource and std.mem.eql(u8, e.token(), tok)) {
                std.mem.copyForwards(Entry, self.entries[i .. self.len - 1], self.entries[i + 1 .. self.len]);
                self.len -= 1;
                return true;
            }
        }
        return false;
    }

    /// Number of active subscriptions.
    pub fn count(self: *const Registry) usize {
        return self.len;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Serialize `note`, parse it back (a real in-memory round-trip), assert its
/// payload, and return the Observe sequence it carried.
fn roundTripNotificationSeq(note: coap.Message, expect_payload: []const u8) !u24 {
    var wire: [128]u8 = undefined;
    const n = try coap.serialize(note, &wire);
    var opts: [8]coap.Option = undefined;
    const parsed = try coap.parse(wire[0..n], &opts);
    try testing.expectEqualStrings(expect_payload, parsed.payload);
    var seq: ?u24 = null;
    for (parsed.options) |o| {
        if (o.number == coap.options.number.observe) seq = decodeValue(o.value);
    }
    return seq orelse error.MissingObserveOption;
}

test "Sequence: monotonic, wraps at 24 bits" {
    var s = Sequence{};
    try testing.expectEqual(@as(u24, 0), s.next());
    try testing.expectEqual(@as(u24, 1), s.next());
    try testing.expectEqual(@as(u24, 2), s.next());

    var w = Sequence{ .value = max_sequence };
    try testing.expectEqual(max_sequence, w.next());
    try testing.expectEqual(@as(u24, 0), w.next()); // wrapped
}

test "isNewer: forward, stale, and wrap-around" {
    try testing.expect(isNewer(0, 1));
    try testing.expect(isNewer(1, 2));
    try testing.expect(!isNewer(2, 1)); // out of order
    try testing.expect(!isNewer(5, 5)); // equal is not newer
    // Wrap: a small value just past the top is newer than a value near the top.
    try testing.expect(isNewer(max_sequence, 0));
    try testing.expect(!isNewer(0, max_sequence));
}

test "encodeValue/decodeValue round-trip (minimal, no leading zeros)" {
    var buf: [3]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{}, encodeValue(0, &buf));
    try testing.expectEqualSlices(u8, &.{60}, encodeValue(60, &buf));
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, encodeValue(256, &buf));
    for ([_]u24{ 0, 1, 255, 256, 65535, 65536, max_sequence }) |v| {
        const enc = encodeValue(v, &buf);
        if (enc.len > 0) try testing.expect(enc[0] != 0);
        try testing.expectEqual(v, decodeValue(enc));
    }
}

test "Registry: register, freshness-checked notify, cancel" {
    var storage: [4]Registry.Entry = undefined;
    var reg = Registry.init(&storage);

    const tok = "\x01\x02\x03\x04";
    _ = reg.register(tok, 42, 0); // initial notification seq 0
    try testing.expectEqual(@as(usize, 1), reg.count());

    // In-order notifications are accepted and advance last_seq.
    try testing.expectEqual(Registry.Update.accepted, reg.notify(tok, 42, 1).?);
    try testing.expectEqual(Registry.Update.accepted, reg.notify(tok, 42, 2).?);
    // A replayed/out-of-order seq is rejected.
    try testing.expectEqual(Registry.Update.stale, reg.notify(tok, 42, 1).?);
    try testing.expectEqual(Registry.Update.stale, reg.notify(tok, 42, 2).?);

    // Unknown (token, resource) → null.
    try testing.expectEqual(@as(?Registry.Update, null), reg.notify(tok, 99, 3));
    try testing.expectEqual(@as(?Registry.Update, null), reg.notify("zzzz", 42, 3));

    // Cancel removes exactly the one entry.
    try testing.expect(reg.cancel(tok, 42));
    try testing.expectEqual(@as(usize, 0), reg.count());
    try testing.expect(!reg.cancel(tok, 42)); // already gone
}

test "Registry: FIFO eviction when full, re-register refreshes" {
    var storage: [2]Registry.Entry = undefined;
    var reg = Registry.init(&storage);

    _ = reg.register("a", 1, 0);
    _ = reg.register("b", 2, 0);
    _ = reg.register("c", 3, 0); // full → evicts the oldest ("a",1)
    try testing.expectEqual(@as(usize, 2), reg.count());
    try testing.expectEqual(@as(?Registry.Update, null), reg.notify("a", 1, 5)); // evicted
    try testing.expectEqual(Registry.Update.accepted, reg.notify("b", 2, 5).?);
    try testing.expectEqual(Registry.Update.accepted, reg.notify("c", 3, 5).?);

    // Re-registering an existing key updates in place (no growth).
    _ = reg.register("b", 2, 10);
    try testing.expectEqual(@as(usize, 2), reg.count());
    try testing.expectEqual(Registry.Update.stale, reg.notify("b", 2, 9).?); // 9 < 10
    try testing.expectEqual(Registry.Update.accepted, reg.notify("b", 2, 11).?);
}

test "C7 end-to-end: observe register → notifications → freshness → cancel" {
    const num = coap.options.number;

    const token = "\x0A\x0B\x0C\x0D";
    const resource: u64 = 0x57A7; // stand-in for a Uri-Path hash

    var srv = coap.server.Server.init(0xC000);
    var seq = Sequence{};

    var sub_store: [4]Registry.Entry = undefined;
    var reg = Registry.init(&sub_store); // server subscription table
    var view_store: [4]Registry.Entry = undefined;
    var view = Registry.init(&view_store); // the client's freshness view

    // 1. client → GET /status with Observe: register (value 0 → empty).
    var obuf: [3]u8 = undefined;
    const get: coap.Message = .{
        .type = .confirmable,
        .code = .get,
        .message_id = 0x01,
        .token = token,
        .options = &.{
            .{ .number = num.observe, .value = encodeValue(request.register, &obuf) },
            .{ .number = num.uri_path, .value = "status" },
        },
    };
    var gwire: [64]u8 = undefined;
    const glen = try coap.serialize(get, &gwire);

    // 2. server parses, confirms it is a register, and registers + notifies.
    var sopts: [8]coap.Option = undefined;
    const sget = try coap.parse(gwire[0..glen], &sopts);
    var registering = false;
    for (sget.options) |o| {
        if (o.number == num.observe) registering = decodeValue(o.value) == request.register;
    }
    try testing.expect(registering);

    const s0 = seq.next(); // 0
    _ = reg.register(sget.token, resource, s0);
    try testing.expectEqual(@as(usize, 1), reg.count());
    {
        var nbuf: [3]u8 = undefined;
        const note = srv.separate(sget, .content, &.{
            .{ .number = num.observe, .value = encodeValue(s0, &nbuf) },
        }, "v0", false);
        const cs = try roundTripNotificationSeq(note, "v0");
        _ = view.register(sget.token, resource, cs); // client records the initial seq
    }

    // 3. two resource changes → two notifications with increasing seq, accepted.
    inline for (.{ "v1", "v2" }) |p| {
        const s = seq.next();
        var nbuf: [3]u8 = undefined;
        const note = srv.separate(sget, .content, &.{
            .{ .number = num.observe, .value = encodeValue(s, &nbuf) },
        }, p, false);
        const cs = try roundTripNotificationSeq(note, p);
        try testing.expectEqual(Registry.Update.accepted, view.notify(token, resource, cs).?);
    }

    // 4. an out-of-order (stale) notification is rejected by the client.
    try testing.expectEqual(Registry.Update.stale, view.notify(token, resource, 1).?);

    // 5. cancellation (an Observe:1 deregister GET, or a RST) removes the entry.
    try testing.expect(reg.cancel(sget.token, resource));
    try testing.expectEqual(@as(usize, 0), reg.count());
}

test "C7 reliability glue: a dead CON notification cancels the subscription" {
    const reliability = coap.reliability;

    var sub_store: [2]Registry.Entry = undefined;
    var reg = Registry.init(&sub_store);
    const token = "\x01";
    const resource: u64 = 7;

    // A CON notification whose Retransmit exhausts (.timed_out) → cancel.
    _ = reg.register(token, resource, 0);
    var rt = reliability.Retransmit.init(.{ .max_retransmit = 0 }, 0, 0);
    try testing.expectEqual(reliability.Retransmit.Action.timed_out, rt.poll(2000));
    if (rt.isDone()) _ = reg.cancel(token, resource);
    try testing.expectEqual(@as(usize, 0), reg.count());

    // A CON notification answered with a Reset (.reset) → cancel.
    _ = reg.register(token, resource, 0);
    var rt2 = reliability.Retransmit.init(.{}, 0, 0);
    rt2.onReset();
    if (rt2.isDone()) _ = reg.cancel(token, resource);
    try testing.expectEqual(@as(usize, 0), reg.count());
}
