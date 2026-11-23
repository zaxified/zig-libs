// SPDX-License-Identifier: MIT

//! Server-side state of RFC 9175 (Echo and Request-Tag): the freshness
//! challenge and the block-wise request-body tracking. The options' numbers and
//! typed accessors live in `options.zig` (`echo`, `requestTags`); this file is
//! what a server does with them. Transport- and clock-agnostic, allocation-free,
//! like the rest of the module: the caller supplies time and a peer identity.
//!
//! **Echo (§2).** A server that wants proof that a request is fresh, or that the
//! sender can receive at its source address (the amplification defence of
//! RFC 7252 §11.3), answers 4.01 Unauthorized with an Echo option holding a value
//! only it can have made. The client repeats the request with that value in its
//! own Echo option; the server accepts it while the value is young enough.
//! `EchoVerifier` is the stateless form of §2.4/§2.6: the value is the issue time
//! plus a keyed MAC over the time and the peer identity, so the server remembers
//! nothing per client. A value is bound to the identity it was issued for, which
//! is what makes it proof about a source address (use the authenticated peer
//! where there is one, the source address and port otherwise).
//!
//! **Request-Tag (§3).** A client uses Request-Tag to keep two block-wise request
//! bodies to the same resource apart, so a malicious in-path actor cannot splice
//! blocks of two operations into one. The server side (§3.3): blocks of one
//! operation carry the same Request-Tag values; a Block1 block with NUM 0 starts a
//! new operation (and replaces an unfinished one of the same client for the same
//! resource); a later block whose tags differ from the operation's, or that
//! belongs to no operation, must not be added to a body (4.08 Request Entity
//! Incomplete, RFC 7959 §2.9.2). `RequestTagTracker` keeps that table over caller
//! storage.

const std = @import("std");
const coap = @import("root.zig");
const block = @import("block.zig");
const options = @import("options.zig");
const server = @import("server.zig");

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

// ── Echo ─────────────────────────────────────────────────────────────────────

pub const EchoVerifier = struct {
    key: [32]u8,
    /// How long an issued value stays fresh, in milliseconds.
    lifetime_ms: u64,

    /// Octets of an issued Echo value: 8 for the issue time, 16 of MAC. Within
    /// RFC 9175's 1..40.
    pub const value_len: usize = 24;
    const mac_len: usize = 16;

    pub const Check = enum {
        /// A value this verifier issued for this peer, still within its lifetime.
        fresh,
        /// Issued by this verifier for this peer, but older than the lifetime (or
        /// from the future: a clock that went backwards): challenge again.
        stale,
        /// Not a value this verifier issued for this peer (wrong length, wrong
        /// MAC, wrong peer).
        invalid,
    };

    /// The key by pointer and the verifier (which holds it) through `out`:
    /// no copy of the key in a caller's frame or result slot.
    pub fn init(out: *EchoVerifier, key: *const [32]u8, lifetime_ms: u64) void {
        out.key = key.*;
        out.lifetime_ms = lifetime_ms;
    }

    fn mac(self: *const EchoVerifier, now_ms: u64, peer: u64) [mac_len]u8 {
        var h = Hmac.init(&self.key);
        var buf: [16]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], now_ms, .big);
        std.mem.writeInt(u64, buf[8..16], peer, .big);
        h.update(&buf);
        var full: [Hmac.mac_length]u8 = undefined;
        h.final(&full);
        return full[0..mac_len].*;
    }

    /// A fresh Echo value for `peer` at `now_ms`.
    pub fn issue(self: *const EchoVerifier, now_ms: u64, peer: u64) [value_len]u8 {
        var v: [value_len]u8 = undefined;
        std.mem.writeInt(u64, v[0..8], now_ms, .big);
        v[8..].* = self.mac(now_ms, peer);
        return v;
    }

    /// Whether `value` (the request's Echo option) proves freshness for `peer`.
    pub fn check(self: *const EchoVerifier, value: []const u8, now_ms: u64, peer: u64) Check {
        if (value.len != value_len) return .invalid;
        const issued = std.mem.readInt(u64, value[0..8], .big);
        const want = self.mac(issued, peer);
        if (!std.crypto.timing_safe.eql([mac_len]u8, want, value[8..][0..mac_len].*)) return .invalid;
        if (issued > now_ms) return .stale;
        if (now_ms - issued > self.lifetime_ms) return .stale;
        return .fresh;
    }
};

/// Storage for the challenge `challenge` builds.
pub const ChallengeBuf = struct {
    value: [EchoVerifier.value_len]u8 = undefined,
    opts: [1]coap.Option = undefined,
};

/// The freshness gate of a request. Null: the request carries a fresh Echo value
/// for `peer`, process it. Otherwise the 4.01 Unauthorized answer with a new
/// Echo challenge (RFC 9175 §2.3), to send in place of the real answer; the
/// client repeats the request with the value. A request whose Echo option is
/// malformed (empty or over 40 octets) is challenged as well.
// secret-api-ok: buf receives the public challenge; the MAC key is read through `verifier` (by pointer) by HMAC-SHA-256, unburned on this per-request path by design: the key only authenticates Echo freshness values (RFC 9175)
pub fn challenge(
    verifier: *const EchoVerifier,
    req: coap.Message,
    now_ms: u64,
    peer: u64,
    buf: *ChallengeBuf,
) ?coap.Message {
    if (options.echo(req) catch null) |v| {
        if (verifier.check(v, now_ms, peer) == .fresh) return null;
    }
    buf.value = verifier.issue(now_ms, peer);
    buf.opts[0] = .{ .number = options.number.echo, .value = &buf.value };
    return server.piggyback(req, .unauthorized, &buf.opts, "");
}

// ── Request-Tag ──────────────────────────────────────────────────────────────

/// Block-wise request operations in progress, one per `(peer, resource)`.
pub const RequestTagTracker = struct {
    entries: []Entry,
    len: usize = 0,

    /// Room for the Request-Tag values of one operation: at most this many
    /// octets in total, as `max_tags` values of up to 8 octets each, joined with
    /// their lengths. Larger sets are refused (`error.TooManyTags`).
    pub const max_tags = 4;

    pub const Entry = struct {
        peer: u64 = 0,
        resource: u64 = 0,
        n_tags: u8 = 0,
        tag_len: [max_tags]u8 = undefined,
        tag: [max_tags][options.request_tag_max_len]u8 = undefined,
        /// The block the operation expects next.
        next_num: u32 = 0,

        fn matches(e: *const Entry, tags: []const []const u8) bool {
            if (e.n_tags != tags.len) return false;
            for (tags, 0..) |t, i| {
                if (!std.mem.eql(u8, e.tag[i][0..e.tag_len[i]], t)) return false;
            }
            return true;
        }
    };

    pub const Error = error{
        /// More Request-Tag options than `max_tags`, or one over 8 octets.
        TooManyTags,
    };

    pub const Verdict = enum {
        /// Add the block to the body.
        accept,
        /// A new operation started (NUM 0): any unfinished one of this peer and
        /// resource is dropped. (Also `accept` semantics: add the block.)
        started,
        /// The block belongs to no operation in progress (it is not NUM 0 and
        /// nothing was started), or skips ahead of it: answer 4.08.
        no_operation,
        /// Its Request-Tag values differ from the operation's: answer 4.08, do
        /// not mix it into the body (RFC 9175 §3.3).
        tag_mismatch,
        /// The table is full of other operations and this one could not start:
        /// answer 5.03 Service Unavailable.
        full,
    };

    pub fn init(storage: []Entry) RequestTagTracker {
        return .{ .entries = storage };
    }

    pub fn count(self: *const RequestTagTracker) usize {
        return self.len;
    }

    fn findIndex(self: *const RequestTagTracker, peer: u64, resource: u64) ?usize {
        for (self.entries[0..self.len], 0..) |e, i| {
            if (e.peer == peer and e.resource == resource) return i;
        }
        return null;
    }

    fn remove(self: *RequestTagTracker, i: usize) void {
        std.mem.copyForwards(Entry, self.entries[i .. self.len - 1], self.entries[i + 1 .. self.len]);
        self.len -= 1;
    }

    /// Judges one Block1 request block of `(peer, resource)` carrying the
    /// Request-Tag values `tags` (in order, as `options.requestTags` yields
    /// them) and the Block1 descriptor `b1`. An accepted final block (M = 0) ends
    /// the operation. Blocks must arrive in order: only the NUM the operation
    /// expects (or a retransmission of the previous one, which is accepted
    /// without moving on) is taken.
    pub fn onBlock(
        self: *RequestTagTracker,
        peer: u64,
        resource: u64,
        tags: []const []const u8,
        b1: block.Block,
    ) Error!Verdict {
        if (tags.len > max_tags) return error.TooManyTags;
        for (tags) |t| if (t.len > options.request_tag_max_len) return error.TooManyTags;
        const idx = self.findIndex(peer, resource);

        if (b1.num == 0) {
            // A new operation replaces an unfinished one of the same client for
            // the same resource.
            if (idx) |i| self.remove(i);
            if (!b1.more) return .started; // a one-block body needs no tracking
            if (self.len == self.entries.len) return .full;
            var e: Entry = .{ .peer = peer, .resource = resource, .n_tags = @intCast(tags.len), .next_num = 1 };
            for (tags, 0..) |t, k| {
                e.tag_len[k] = @intCast(t.len);
                @memcpy(e.tag[k][0..t.len], t);
            }
            self.entries[self.len] = e;
            self.len += 1;
            return .started;
        }

        const i = idx orelse return .no_operation;
        const e = &self.entries[i];
        if (!e.matches(tags)) return .tag_mismatch;
        if (b1.num + 1 == e.next_num) return .accept; // a retransmission of the previous block
        if (b1.num != e.next_num) return .no_operation;
        if (!b1.more) {
            self.remove(i);
        } else {
            e.next_num += 1;
        }
        return .accept;
    }

    /// Forgets the operations of `peer` (its connection or session ended).
    pub fn dropPeer(self: *RequestTagTracker, peer: u64) void {
        var i: usize = 0;
        while (i < self.len) {
            if (self.entries[i].peer == peer) self.remove(i) else i += 1;
        }
    }
};

/// The Request-Tag values of `req` collected into `out`; `error.TooManyTags` when
/// there are more than fit, or a value is over 8 octets.
pub fn collectTags(req: coap.Message, out: [][]const u8) RequestTagTracker.Error![][]const u8 {
    var it = options.requestTags(req);
    var n: usize = 0;
    while (it.next() catch return error.TooManyTags) |t| {
        if (n == out.len) return error.TooManyTags;
        out[n] = t;
        n += 1;
    }
    return out[0..n];
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn echoReq(value: ?[]const u8, store: *[2]coap.Option) coap.Message {
    var n: usize = 0;
    store[n] = .{ .number = options.number.uri_path, .value = "r" };
    n += 1;
    if (value) |v| {
        store[n] = .{ .number = options.number.echo, .value = v };
        n += 1;
    }
    return .{ .type = .confirmable, .code = .get, .message_id = 0x99, .token = &.{ 5, 5 }, .options = store[0..n] };
}

test "Echo: issue and check, bound to time and peer" {
    var v: EchoVerifier = undefined;
    EchoVerifier.init(&v, &@as([32]u8, @splat(0x42)), 1000);
    const val = v.issue(5000, 77);
    try testing.expectEqual(EchoVerifier.value_len, val.len);
    try testing.expect(val.len >= 1 and val.len <= options.echo_max_len);
    try testing.expectEqual(EchoVerifier.Check.fresh, v.check(&val, 5000, 77));
    try testing.expectEqual(EchoVerifier.Check.fresh, v.check(&val, 6000, 77)); // exactly the lifetime
    try testing.expectEqual(EchoVerifier.Check.stale, v.check(&val, 6001, 77));
    try testing.expectEqual(EchoVerifier.Check.stale, v.check(&val, 4999, 77)); // from the future
    // Another peer cannot use it.
    try testing.expectEqual(EchoVerifier.Check.invalid, v.check(&val, 5000, 78));
    // Another key neither.
    var other: EchoVerifier = undefined;
    EchoVerifier.init(&other, &@as([32]u8, @splat(0x43)), 1000);
    try testing.expectEqual(EchoVerifier.Check.invalid, other.check(&val, 5000, 77));
    // Every octet matters: flip each one.
    for (0..val.len) |i| {
        var bad = val;
        bad[i] ^= 1;
        try testing.expect(v.check(&bad, 5000, 77) != .fresh);
    }
    // Wrong lengths.
    try testing.expectEqual(EchoVerifier.Check.invalid, v.check(val[0..23], 5000, 77));
    try testing.expectEqual(EchoVerifier.Check.invalid, v.check(&.{}, 5000, 77));
    var long: [25]u8 = undefined;
    @memcpy(long[0..24], &val);
    long[24] = 0;
    try testing.expectEqual(EchoVerifier.Check.invalid, v.check(&long, 5000, 77));
    // A timestamp altered together with nothing else fails the MAC.
    var shifted = val;
    shifted[7] +%= 1;
    try testing.expectEqual(EchoVerifier.Check.invalid, v.check(&shifted, 5001, 77));
}

test "Echo: the challenge answers 4.01 with an Echo value and lets a fresh repeat through" {
    var v: EchoVerifier = undefined;
    EchoVerifier.init(&v, &@as([32]u8, @splat(7)), 2000);
    var st: [2]coap.Option = undefined;
    var cb: ChallengeBuf = .{};
    // No Echo: challenged.
    const c1 = challenge(&v, echoReq(null, &st), 100, 9, &cb).?;
    try testing.expectEqual(coap.Type.ack, c1.type);
    try testing.expectEqual(coap.Code.unauthorized, c1.code);
    try testing.expectEqual(@as(u16, 0x99), c1.message_id);
    try testing.expectEqualSlices(u8, &.{ 5, 5 }, c1.token);
    const echo_val = (try options.echo(c1)).?;
    try testing.expectEqual(EchoVerifier.value_len, echo_val.len);
    // The client repeats the request with the value: accepted (null) while fresh.
    var held: [EchoVerifier.value_len]u8 = undefined;
    @memcpy(&held, echo_val);
    var st2: [2]coap.Option = undefined;
    try testing.expect(challenge(&v, echoReq(&held, &st2), 1500, 9, &cb) == null);
    // Too late: challenged again with a new value.
    const c2 = challenge(&v, echoReq(&held, &st2), 2101, 9, &cb).?;
    try testing.expectEqual(coap.Code.unauthorized, c2.code);
    try testing.expect(!std.mem.eql(u8, &held, (try options.echo(c2)).?));
    // From another peer: challenged.
    try testing.expect(challenge(&v, echoReq(&held, &st2), 1500, 10, &cb) != null);
    // A malformed Echo (empty) is challenged, not an error.
    try testing.expect(challenge(&v, echoReq(&.{}, &st2), 1500, 9, &cb) != null);
}

fn tagList(comptime n: usize, vals: [n][]const u8) [n][]const u8 {
    return vals;
}

test "Request-Tag: blocks of one operation are accepted, a different tag is not mixed in" {
    var store: [4]RequestTagTracker.Entry = undefined;
    var t = RequestTagTracker.init(&store);
    const a = tagList(1, .{"A1"});
    const b = tagList(1, .{"B2"});
    const none = [_][]const u8{};

    try testing.expectEqual(RequestTagTracker.Verdict.started, try t.onBlock(1, 10, &a, .{ .num = 0, .more = true, .szx = 2 }));
    try testing.expectEqual(@as(usize, 1), t.count());
    try testing.expectEqual(RequestTagTracker.Verdict.accept, try t.onBlock(1, 10, &a, .{ .num = 1, .more = true, .szx = 2 }));
    // A block of another operation (other tag) is not mixed in; the operation survives.
    try testing.expectEqual(RequestTagTracker.Verdict.tag_mismatch, try t.onBlock(1, 10, &b, .{ .num = 2, .more = true, .szx = 2 }));
    try testing.expectEqual(RequestTagTracker.Verdict.tag_mismatch, try t.onBlock(1, 10, &none, .{ .num = 2, .more = true, .szx = 2 }));
    // A retransmission of the previous block is accepted without moving on.
    try testing.expectEqual(RequestTagTracker.Verdict.accept, try t.onBlock(1, 10, &a, .{ .num = 1, .more = true, .szx = 2 }));
    // A skipped block is refused.
    try testing.expectEqual(RequestTagTracker.Verdict.no_operation, try t.onBlock(1, 10, &a, .{ .num = 3, .more = true, .szx = 2 }));
    try testing.expectEqual(RequestTagTracker.Verdict.accept, try t.onBlock(1, 10, &a, .{ .num = 2, .more = false, .szx = 2 }));
    // The final block ended the operation: a straggler belongs to nothing.
    try testing.expectEqual(@as(usize, 0), t.count());
    try testing.expectEqual(RequestTagTracker.Verdict.no_operation, try t.onBlock(1, 10, &a, .{ .num = 3, .more = false, .szx = 2 }));
}

test "Request-Tag: operations are per peer and resource, NUM 0 restarts, the table is bounded" {
    var store: [2]RequestTagTracker.Entry = undefined;
    var t = RequestTagTracker.init(&store);
    const a = tagList(1, .{"A"});
    const b = tagList(1, .{"B"});
    try testing.expectEqual(RequestTagTracker.Verdict.started, try t.onBlock(1, 10, &a, .{ .num = 0, .more = true, .szx = 0 }));
    try testing.expectEqual(RequestTagTracker.Verdict.started, try t.onBlock(2, 10, &b, .{ .num = 0, .more = true, .szx = 0 }));
    // Same resource, different peers: independent.
    try testing.expectEqual(RequestTagTracker.Verdict.accept, try t.onBlock(2, 10, &b, .{ .num = 1, .more = true, .szx = 0 }));
    try testing.expectEqual(RequestTagTracker.Verdict.accept, try t.onBlock(1, 10, &a, .{ .num = 1, .more = true, .szx = 0 }));
    // A third operation does not fit.
    try testing.expectEqual(RequestTagTracker.Verdict.full, try t.onBlock(3, 10, &a, .{ .num = 0, .more = true, .szx = 0 }));
    // Same peer, another resource: also a new operation (and full).
    try testing.expectEqual(RequestTagTracker.Verdict.full, try t.onBlock(1, 11, &a, .{ .num = 0, .more = true, .szx = 0 }));
    // NUM 0 with a new tag replaces the peer's unfinished operation for the resource.
    try testing.expectEqual(RequestTagTracker.Verdict.started, try t.onBlock(1, 10, &b, .{ .num = 0, .more = true, .szx = 0 }));
    try testing.expectEqual(@as(usize, 2), t.count());
    try testing.expectEqual(RequestTagTracker.Verdict.tag_mismatch, try t.onBlock(1, 10, &a, .{ .num = 1, .more = true, .szx = 0 }));
    try testing.expectEqual(RequestTagTracker.Verdict.accept, try t.onBlock(1, 10, &b, .{ .num = 1, .more = true, .szx = 0 }));
    // A one-block body is no operation, and clears an unfinished one.
    try testing.expectEqual(RequestTagTracker.Verdict.started, try t.onBlock(1, 10, &a, .{ .num = 0, .more = false, .szx = 0 }));
    try testing.expectEqual(@as(usize, 1), t.count());
    // dropPeer forgets one peer's operations.
    t.dropPeer(2);
    try testing.expectEqual(@as(usize, 0), t.count());
    t.dropPeer(2);
}

test "Request-Tag: tag sets, limits, and collectTags over a parsed request" {
    var store: [2]RequestTagTracker.Entry = undefined;
    var t = RequestTagTracker.init(&store);
    // Several tags: all must match, in order.
    const ab = tagList(2, .{ "a", "b" });
    const ba = tagList(2, .{ "b", "a" });
    const a = tagList(1, .{"a"});
    try testing.expectEqual(RequestTagTracker.Verdict.started, try t.onBlock(1, 1, &ab, .{ .num = 0, .more = true, .szx = 0 }));
    try testing.expectEqual(RequestTagTracker.Verdict.tag_mismatch, try t.onBlock(1, 1, &ba, .{ .num = 1, .more = true, .szx = 0 }));
    try testing.expectEqual(RequestTagTracker.Verdict.tag_mismatch, try t.onBlock(1, 1, &a, .{ .num = 1, .more = true, .szx = 0 }));
    try testing.expectEqual(RequestTagTracker.Verdict.accept, try t.onBlock(1, 1, &ab, .{ .num = 1, .more = true, .szx = 0 }));
    // An empty tag is a tag, distinct from none.
    const empty_tag = tagList(1, .{""});
    try testing.expectEqual(RequestTagTracker.Verdict.started, try t.onBlock(2, 2, &empty_tag, .{ .num = 0, .more = true, .szx = 0 }));
    try testing.expectEqual(RequestTagTracker.Verdict.tag_mismatch, try t.onBlock(2, 2, &.{}, .{ .num = 1, .more = true, .szx = 0 }));
    try testing.expectEqual(RequestTagTracker.Verdict.accept, try t.onBlock(2, 2, &empty_tag, .{ .num = 1, .more = true, .szx = 0 }));
    // Limits.
    const five = tagList(5, .{ "1", "2", "3", "4", "5" });
    try testing.expectError(error.TooManyTags, t.onBlock(3, 3, &five, .{ .num = 0, .more = true, .szx = 0 }));
    const long = tagList(1, .{"123456789"});
    try testing.expectError(error.TooManyTags, t.onBlock(3, 3, &long, .{ .num = 0, .more = true, .szx = 0 }));
    // collectTags reads the repeatable option in order.
    const opts = [_]coap.Option{
        .{ .number = options.number.request_tag, .value = "x" },
        .{ .number = options.number.request_tag, .value = "" },
        .{ .number = options.number.request_tag, .value = "yz" },
    };
    const req: coap.Message = .{ .type = .confirmable, .code = .put, .message_id = 1, .options = &opts };
    var out: [4][]const u8 = undefined;
    const got = try collectTags(req, &out);
    try testing.expectEqual(@as(usize, 3), got.len);
    try testing.expectEqualStrings("yz", got[2]);
    var small: [2][]const u8 = undefined;
    try testing.expectError(error.TooManyTags, collectTags(req, &small));
    const bad_opts = [_]coap.Option{.{ .number = options.number.request_tag, .value = "123456789" }};
    try testing.expectError(error.TooManyTags, collectTags(.{ .type = .confirmable, .code = .put, .message_id = 1, .options = &bad_opts }, &out));
}
