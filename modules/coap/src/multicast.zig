// SPDX-License-Identifier: MIT

//! Multicast request handling (RFC 7252 §8, which RFC 7390 group communication
//! builds on): what a client may send to a group address and when and how a
//! server answers. The module sends nothing itself; these are the decisions and
//! numbers, so a server loop and a client can follow the rules without
//! re-deriving them.
//!
//! - **Requests are Non-confirmable** (§8.1): a Confirmable request to a
//!   multicast address is not valid (`requestAllowed`).
//! - **Answers are Non-confirmable and delayed** (§8.2): the server picks a random
//!   point within its *Leisure* to answer, so the group's answers do not arrive
//!   together. `leisureMs` is §8.2's `S * G / R`, `default_leisure_ms` the
//!   5-second fallback (§4.8.2, DEFAULT_LEISURE), `responseDelayMs` the draw. A
//!   server tracks that the request came by multicast itself (the destination
//!   address is the transport's), and may then also pass `DispatchOptions
//!   .multicast` to the resource dispatcher so unmatched discovery stays silent.
//! - **Errors are not answered** (§8.2): a server may ignore a multicast request
//!   it cannot satisfy; `shouldAnswer` returns false for 4.xx/5.xx.
//! - The "All CoAP Nodes" addresses (§12.8) are `all_coap_nodes_ipv4` and the
//!   `ipv6` scopes.
//!
//! RFC 7390 itself defines group management resources (a JSON document at the
//! group-manager's `/gm` path) and the Group-ID/URI conventions on top of this; the
//! management side is ordinary resource handling and has no codec here.

const std = @import("std");
const coap = @import("root.zig");

/// DEFAULT_LEISURE (RFC 7252 §4.8.2): 5 seconds.
pub const default_leisure_ms: u64 = 5000;

/// "All CoAP Nodes" (RFC 7252 §12.8): the IPv4 multicast address and the IPv6
/// addresses at the link-local and site-local scope.
pub const all_coap_nodes_ipv4 = [4]u8{ 224, 0, 1, 187 };
pub const all_coap_nodes_ipv6_link_local = [16]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd };
pub const all_coap_nodes_ipv6_site_local = [16]u8{ 0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd };

/// Whether `req` is a valid request to a multicast address: Non-confirmable
/// (§8.1). A Confirmable one must not be sent to a group, and a server that
/// receives one by multicast should drop it.
pub fn requestAllowed(req: coap.Message) bool {
    return req.type == .non_confirmable;
}

/// §8.2's Leisure in milliseconds: `S * G / R` with `response_size` S in octets,
/// `group_size` G (the server's estimate of the number of answering servers) and
/// `rate_bytes_per_s` R (the target data transfer rate for the answers, octets
/// per second). Without a usable estimate (G or R of zero) it is
/// `default_leisure_ms`. Saturates instead of overflowing.
pub fn leisureMs(response_size: u64, group_size: u64, rate_bytes_per_s: u64) u64 {
    if (group_size == 0 or rate_bytes_per_s == 0) return default_leisure_ms;
    const num = std.math.mul(u64, std.math.mul(u64, response_size, group_size) catch return std.math.maxInt(u64), 1000) catch return std.math.maxInt(u64);
    return num / rate_bytes_per_s;
}

/// A delay drawn uniformly from `0..=leisure_ms`: when to send the answer.
pub fn responseDelayMs(random: std.Random, leisure_ms: u64) u64 {
    if (leisure_ms == 0) return 0;
    if (leisure_ms == std.math.maxInt(u64)) return random.int(u64);
    return random.uintAtMost(u64, leisure_ms);
}

/// The message type of the answer to a multicast request: always
/// Non-confirmable and separate (a piggybacked ACK would acknowledge a message
/// that is not Confirmable).
pub const answer_type: coap.Type = .non_confirmable;

/// Whether to answer a multicast request with `code`: success answers (2.xx)
/// go out, 4.xx and 5.xx are dropped (§8.2). Anything else (a signaling code, an
/// empty message) is not an answer to a request and is not sent either.
pub fn shouldAnswer(code: coap.Code) bool {
    return code.class() == 2;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "requests to a group address must be Non-confirmable" {
    const base: coap.Message = .{ .type = .non_confirmable, .code = .get, .message_id = 1 };
    try testing.expect(requestAllowed(base));
    var con = base;
    con.type = .confirmable;
    try testing.expect(!requestAllowed(con));
    var ack = base;
    ack.type = .ack;
    try testing.expect(!requestAllowed(ack));
    var rst = base;
    rst.type = .reset;
    try testing.expect(!requestAllowed(rst));
}

test "Leisure is S*G/R, the default without an estimate, saturating" {
    // 100 octets, 50 servers, 1000 octets/s: 5 s.
    try testing.expectEqual(@as(u64, 5000), leisureMs(100, 50, 1000));
    // 1 octet, 1 server, 1 octet/s: one second.
    try testing.expectEqual(@as(u64, 1000), leisureMs(1, 1, 1));
    try testing.expectEqual(default_leisure_ms, leisureMs(100, 0, 1000));
    try testing.expectEqual(default_leisure_ms, leisureMs(100, 50, 0));
    try testing.expectEqual(@as(u64, 0), leisureMs(0, 50, 1000));
    try testing.expectEqual(std.math.maxInt(u64), leisureMs(std.math.maxInt(u64), 2, 1));
    try testing.expectEqual(std.math.maxInt(u64), leisureMs(1 << 60, 1, 1));
}

test "the response delay lies within the Leisure and uses it all" {
    var prng = std.Random.DefaultPrng.init(0x7252);
    const r = prng.random();
    var lo: u64 = std.math.maxInt(u64);
    var hi: u64 = 0;
    for (0..2000) |_| {
        const d = responseDelayMs(r, 5000);
        try testing.expect(d <= 5000);
        lo = @min(lo, d);
        hi = @max(hi, d);
    }
    try testing.expect(lo < 250 and hi > 4750);
    try testing.expectEqual(@as(u64, 0), responseDelayMs(r, 0));
    // The unbounded Leisure draws over the whole range without overflow.
    _ = responseDelayMs(r, std.math.maxInt(u64));
}

test "only success answers go to a multicast request" {
    try testing.expect(shouldAnswer(.content));
    try testing.expect(shouldAnswer(.changed));
    try testing.expect(shouldAnswer(.@"continue"));
    try testing.expect(!shouldAnswer(.not_found));
    try testing.expect(!shouldAnswer(.bad_request));
    try testing.expect(!shouldAnswer(.internal_server_error));
    try testing.expect(!shouldAnswer(.empty));
    try testing.expect(!shouldAnswer(.get));
    try testing.expectEqual(coap.Type.non_confirmable, answer_type);
}

test "All CoAP Nodes addresses (RFC 7252 §12.8)" {
    try testing.expectEqualSlices(u8, &.{ 224, 0, 1, 187 }, &all_coap_nodes_ipv4);
    try testing.expectEqual(@as(u8, 0xfd), all_coap_nodes_ipv6_link_local[15]);
    try testing.expectEqual(@as(u8, 0x02), all_coap_nodes_ipv6_link_local[1]);
    try testing.expectEqual(@as(u8, 0x05), all_coap_nodes_ipv6_site_local[1]);
}
