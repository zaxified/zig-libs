// SPDX-License-Identifier: MIT
//! sntp — SNTP client (RFC 4330): build a client request, decode the server
//! reply, and compute clock offset + round-trip delay from the four NTP
//! timestamps (T1 send, T2 server-receive, T3 server-transmit, T4 local-receive).
//!
//! Two layers:
//!   * a pure 48-byte packet codec (`Packet`, `encodeRequest`, `decodeResponse`,
//!     `Timestamp`) — no I/O, golden-byte tested;
//!   * a blocking `query` convenience over `std.Io.net` UDP (IPv4 + IPv6) that
//!     fills T1/T4 from the local clock and returns the computed offset/delay.
//!
//! Epoch model: NTP timestamps are 64-bit fixed-point seconds since the NTP
//! epoch 1900-01-01 (high 32 bits = seconds, low 32 bits = 1/2^32-second
//! fraction), big-endian on the wire. Unix time is `NTP − 2208988800 s`.
//! std's `std.time` timestamp helpers were removed in 0.16, so the local
//! send/receive instants come from `std.posix.system.clock_gettime(.REALTIME)`
//! (libc-free — the repo's pure-Zig invariant).

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;

pub const meta = .{
    .platform = .any,
    .role = .client,
    .concurrency = .reentrant,
    .model_after = "RFC 4330 SNTP; design after FObersteiner/ntp_client",
    .deps = .{}, // std only (std.Io.net for the UDP query)
};

/// Wire size of an SNTP/NTP packet without an optional authenticator (RFC 4330 §4).
pub const packet_len = 48;

/// UDP port assigned to NTP (RFC 4330 §5). Callers still supply the full
/// address (with port) to `query`; this is provided for convenience.
pub const ntp_port: u16 = 123;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01):
/// 70 years, 17 of them leap. RFC 4330 §3.
pub const ntp_unix_offset_s: u64 = 2_208_988_800;

/// The same offset expressed in nanoseconds, as i128 (for signed arithmetic).
pub const ntp_unix_offset_ns: i128 = @as(i128, ntp_unix_offset_s) * std.time.ns_per_s;

// ── field enums ─────────────────────────────────────────────────────────────

/// Leap Indicator (RFC 4330 §4): warns of an impending leap second.
pub const LeapIndicator = enum(u2) {
    no_warning = 0,
    last_minute_61 = 1, // last minute of the day has 61 seconds
    last_minute_59 = 2, // last minute of the day has 59 seconds
    /// Alarm condition — clock not synchronized. Also the value in a
    /// Kiss-o'-Death packet.
    unsynchronized = 3,
};

/// Association mode (RFC 4330 §4). A client sends `.client`; a well-behaved
/// server answers with `.server`.
pub const Mode = enum(u3) {
    reserved = 0,
    symmetric_active = 1,
    symmetric_passive = 2,
    client = 3,
    server = 4,
    broadcast = 5,
    control = 6,
    private = 7,
};

// ── NTP timestamp (32.32 fixed-point seconds since 1900) ────────────────────

/// A 64-bit NTP timestamp: `seconds` since the NTP epoch and a `fraction` in
/// units of 1/2^32 second. Big-endian on the wire.
pub const Timestamp = struct {
    seconds: u32 = 0,
    fraction: u32 = 0,

    /// The all-zero timestamp — RFC 4330 uses it to mean "not set" (e.g. a
    /// request with no reference/originate/receive timestamps).
    pub const zero: Timestamp = .{ .seconds = 0, .fraction = 0 };

    pub fn isZero(self: Timestamp) bool {
        return self.seconds == 0 and self.fraction == 0;
    }

    /// Read 8 big-endian bytes.
    pub fn fromBytes(bytes: *const [8]u8) Timestamp {
        return .{
            .seconds = std.mem.readInt(u32, bytes[0..4], .big),
            .fraction = std.mem.readInt(u32, bytes[4..8], .big),
        };
    }

    /// Write 8 big-endian bytes.
    pub fn toBytes(self: Timestamp) [8]u8 {
        var out: [8]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.seconds, .big);
        std.mem.writeInt(u32, out[4..8], self.fraction, .big);
        return out;
    }

    /// Total nanoseconds since the NTP epoch (1900). Fits in u64 across the
    /// whole NTP era-0 range (max ≈ 4.29e18 ns).
    pub fn nanosSinceNtpEpoch(self: Timestamp) u64 {
        const frac_ns: u64 = (@as(u64, self.fraction) * std.time.ns_per_s) >> 32;
        return @as(u64, self.seconds) * std.time.ns_per_s + frac_ns;
    }

    /// Inverse of `nanosSinceNtpEpoch`. The seconds field wraps modulo 2^32
    /// (NTP era rollover, per RFC 4330 §3 — the expected behavior).
    pub fn fromNanosSinceNtpEpoch(ns: u64) Timestamp {
        const secs: u64 = ns / std.time.ns_per_s;
        const rem: u64 = ns % std.time.ns_per_s;
        const frac: u64 = (rem << 32) / std.time.ns_per_s;
        return .{
            .seconds = @truncate(secs),
            .fraction = @intCast(frac),
        };
    }

    /// Nanoseconds since the Unix epoch (1970). Signed to represent instants
    /// before 1970 and to compose into offset/delay differences.
    pub fn toUnixNanos(self: Timestamp) i128 {
        return @as(i128, self.nanosSinceNtpEpoch()) - ntp_unix_offset_ns;
    }

    /// Build a timestamp from nanoseconds since the Unix epoch.
    pub fn fromUnixNanos(unix_ns: i128) Timestamp {
        const ntp_ns: i128 = unix_ns + ntp_unix_offset_ns;
        if (ntp_ns <= 0) return .zero;
        return fromNanosSinceNtpEpoch(@intCast(ntp_ns));
    }
};

// ── 48-byte packet codec ────────────────────────────────────────────────────

/// A parsed SNTP/NTP packet. `root_delay` and `root_dispersion` are kept as
/// raw 32-bit NTP "short format" fixed-point (16.16 seconds); use
/// `rootDelaySeconds` / `rootDispersionSeconds` to interpret them.
pub const Packet = struct {
    leap: LeapIndicator = .no_warning,
    version: u3 = 4,
    mode: Mode = .client,
    stratum: u8 = 0,
    /// Poll interval, log2 seconds (signed).
    poll: i8 = 0,
    /// Clock precision, log2 seconds (signed, typically negative).
    precision: i8 = 0,
    root_delay: u32 = 0,
    root_dispersion: u32 = 0,
    reference_id: [4]u8 = .{ 0, 0, 0, 0 },
    reference: Timestamp = .zero,
    originate: Timestamp = .zero, // T1
    receive: Timestamp = .zero, // T2
    transmit: Timestamp = .zero, // T3

    /// Interpret a 16.16 fixed-point "NTP short" field as seconds.
    fn shortSeconds(raw: u32) f64 {
        return @as(f64, @floatFromInt(raw)) / 65536.0;
    }

    pub fn rootDelaySeconds(self: Packet) f64 {
        return shortSeconds(self.root_delay);
    }

    pub fn rootDispersionSeconds(self: Packet) f64 {
        return shortSeconds(self.root_dispersion);
    }

    /// Serialize to the 48 wire bytes (big-endian).
    pub fn encode(self: Packet) [packet_len]u8 {
        var out: [packet_len]u8 = undefined;
        out[0] = (@as(u8, @intFromEnum(self.leap)) << 6) |
            (@as(u8, self.version) << 3) |
            @as(u8, @intFromEnum(self.mode));
        out[1] = self.stratum;
        out[2] = @bitCast(self.poll);
        out[3] = @bitCast(self.precision);
        std.mem.writeInt(u32, out[4..8], self.root_delay, .big);
        std.mem.writeInt(u32, out[8..12], self.root_dispersion, .big);
        @memcpy(out[12..16], &self.reference_id);
        @memcpy(out[16..24], &self.reference.toBytes());
        @memcpy(out[24..32], &self.originate.toBytes());
        @memcpy(out[32..40], &self.receive.toBytes());
        @memcpy(out[40..48], &self.transmit.toBytes());
        return out;
    }

    /// Parse exactly 48 bytes. No structural validation beyond length — see
    /// `decodeResponse` for the client-side response checks.
    pub fn decode(bytes: []const u8) error{InvalidLength}!Packet {
        if (bytes.len != packet_len) return error.InvalidLength;
        const b0 = bytes[0];
        return .{
            .leap = @enumFromInt(@as(u2, @truncate(b0 >> 6))),
            .version = @truncate(b0 >> 3),
            .mode = @enumFromInt(@as(u3, @truncate(b0))),
            .stratum = bytes[1],
            .poll = @bitCast(bytes[2]),
            .precision = @bitCast(bytes[3]),
            .root_delay = std.mem.readInt(u32, bytes[4..8], .big),
            .root_dispersion = std.mem.readInt(u32, bytes[8..12], .big),
            .reference_id = bytes[12..16].*,
            .reference = Timestamp.fromBytes(bytes[16..24]),
            .originate = Timestamp.fromBytes(bytes[24..32]),
            .receive = Timestamp.fromBytes(bytes[32..40]),
            .transmit = Timestamp.fromBytes(bytes[40..48]),
        };
    }
};

/// Build a client-mode (mode 3), version-4 request into `out`, with the
/// transmit timestamp (T1) set. All other fields are zero, per RFC 4330 §5
/// (a client SHOULD set only the mode, version and transmit timestamp).
pub fn encodeRequest(out: *[packet_len]u8, transmit: Timestamp) void {
    const p: Packet = .{
        .leap = .no_warning,
        .version = 4,
        .mode = .client,
        .transmit = transmit,
    };
    out.* = p.encode();
}

/// Errors from validating a server response.
pub const DecodeError = error{
    /// Not exactly 48 bytes.
    InvalidLength,
    /// The reply is not in server mode (mode 4).
    NotServerMode,
    /// Stratum 0 — a Kiss-o'-Death packet (RFC 4330 §8). The four ASCII bytes
    /// of the kiss code are in `reference_id`; inspect the returned packet via
    /// `decode` if you need them.
    KissOfDeath,
};

/// A validated server reply. Alias of `Packet` — the `originate`/`receive`/
/// `transmit` fields carry T1/T2/T3 respectively.
pub const Reply = Packet;

/// Decode + validate a server response: exactly 48 bytes, server mode, and
/// non-zero stratum (stratum 0 is surfaced as `error.KissOfDeath`).
pub fn decodeResponse(bytes: []const u8) DecodeError!Reply {
    const p = Packet.decode(bytes) catch return error.InvalidLength;
    if (p.mode != .server) return error.NotServerMode;
    if (p.stratum == 0) return error.KissOfDeath;
    return p;
}

// ── offset / round-trip delay ───────────────────────────────────────────────

/// The four NTP timestamps of one exchange, from which offset and delay are
/// derived (RFC 4330 §5):
///   T1 originate  — client transmit time
///   T2 receive    — server receive time
///   T3 transmit   — server transmit time
///   T4 destination— client receive time
pub const Sample = struct {
    originate: Timestamp, // T1
    receive: Timestamp, // T2
    transmit: Timestamp, // T3
    destination: Timestamp, // T4

    /// Clock offset in nanoseconds: `((T2−T1)+(T3−T4))/2`. Positive means the
    /// server clock is ahead of the local clock.
    pub fn offsetNanos(self: Sample) i128 {
        return computeOffsetNanos(self.originate, self.receive, self.transmit, self.destination);
    }

    /// Round-trip delay in nanoseconds: `(T4−T1)−(T3−T2)`.
    pub fn roundtripDelayNanos(self: Sample) i128 {
        return computeDelayNanos(self.originate, self.receive, self.transmit, self.destination);
    }
};

/// Clock offset `((T2−T1)+(T3−T4))/2` in nanoseconds.
pub fn computeOffsetNanos(t1: Timestamp, t2: Timestamp, t3: Timestamp, t4: Timestamp) i128 {
    const a = @as(i128, t2.nanosSinceNtpEpoch()) - @as(i128, t1.nanosSinceNtpEpoch());
    const b = @as(i128, t3.nanosSinceNtpEpoch()) - @as(i128, t4.nanosSinceNtpEpoch());
    return @divTrunc(a + b, 2);
}

/// Round-trip delay `(T4−T1)−(T3−T2)` in nanoseconds.
pub fn computeDelayNanos(t1: Timestamp, t2: Timestamp, t3: Timestamp, t4: Timestamp) i128 {
    const round = @as(i128, t4.nanosSinceNtpEpoch()) - @as(i128, t1.nanosSinceNtpEpoch());
    const server = @as(i128, t3.nanosSinceNtpEpoch()) - @as(i128, t2.nanosSinceNtpEpoch());
    return round - server;
}

// ── local clock ─────────────────────────────────────────────────────────────

/// Current wall-clock instant as nanoseconds since the Unix epoch. std's
/// `std.time` timestamp helpers were removed in 0.16; this uses the libc-free
/// `clock_gettime(REALTIME)` errno form (and `RtlGetSystemTimePrecise` on
/// Windows), matching the sibling modules (jwt/jobqueue).
pub fn nowUnixNanos() i128 {
    switch (builtin.os.tag) {
        .windows => {
            // 100 ns ticks since 1601-01-01; shift to the Unix epoch, then to ns.
            const hns: i64 = std.os.windows.ntdll.RtlGetSystemTimePrecise();
            return @as(i128, hns - 116444736000000000) * 100;
        },
        else => {
            var ts: std.posix.timespec = undefined;
            if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
            return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
        },
    }
}

/// Current instant as an NTP `Timestamp`.
pub fn nowTimestamp() Timestamp {
    return Timestamp.fromUnixNanos(nowUnixNanos());
}

// ── UDP query ───────────────────────────────────────────────────────────────

pub const QueryOptions = struct {
    /// Receive budget; 0 = wait indefinitely (OS default).
    timeout_ms: u32 = 5000,
    /// Protocol version to advertise in the request.
    version: u3 = 4,
};

pub const QueryError = error{
    Timeout,
    Canceled,
    /// Any socket-level failure (bind/send/receive).
    NetworkFailed,
} || DecodeError;

/// Result of a successful `query`: the validated server reply, the four
/// timestamps, and the derived offset/delay in nanoseconds.
pub const QueryResult = struct {
    reply: Reply,
    sample: Sample,
    offset_ns: i128,
    roundtrip_ns: i128,
};

/// Perform one SNTP exchange with `server` (address must include the NTP port,
/// e.g. `try std.Io.net.IpAddress.parse("162.159.200.1", 123)`), over UDP.
/// Works for IPv4 and IPv6. Fills T1 just before sending and T4 right after
/// receiving, then validates the reply and computes offset + delay.
pub fn query(io: std.Io, server: net.IpAddress, options: QueryOptions) QueryError!QueryResult {
    // Bind a datagram socket on the wildcard address of the server's family.
    const bind_addr: net.IpAddress = switch (server) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const sock = bind_addr.bind(io, .{ .mode = .dgram }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.NetworkFailed,
    };
    defer sock.close(io);

    // T1: build + send the request.
    const t1 = nowTimestamp();
    const req_pkt: Packet = .{ .version = options.version, .mode = .client, .transmit = t1 };
    const request = req_pkt.encode();

    const dest = server;
    sock.send(io, &dest, &request) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.NetworkFailed,
    };

    // Receive the reply from the server, ignoring datagrams from other peers.
    const deadline = deadlineFromMs(io, options.timeout_ms);
    var rbuf: [packet_len]u8 = undefined;
    while (true) {
        const incoming = sock.receiveTimeout(io, &rbuf, deadline) catch |err| switch (err) {
            error.Timeout => return error.Timeout,
            error.Canceled => return error.Canceled,
            else => return error.NetworkFailed,
        };
        if (!incoming.from.eql(&dest)) continue;

        // T4: local receive instant.
        const t4 = nowTimestamp();
        const reply = try decodeResponse(incoming.data);
        const sample: Sample = .{
            .originate = reply.originate, // T1 as echoed by the server
            .receive = reply.receive, // T2
            .transmit = reply.transmit, // T3
            .destination = t4, // T4
        };
        return .{
            .reply = reply,
            .sample = sample,
            .offset_ns = sample.offsetNanos(),
            .roundtrip_ns = sample.roundtripDelayNanos(),
        };
    }
}

fn deadlineFromMs(io: std.Io, ms: u32) std.Io.Timeout {
    if (ms == 0) return .none;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
    return t.toDeadline(io);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "encodeRequest: LI|VN|Mode byte and layout" {
    const t1: Timestamp = .{ .seconds = 0xDEAD_BEEF, .fraction = 0x1234_5678 };
    var out: [packet_len]u8 = undefined;
    encodeRequest(&out, t1);

    // LI=0, VN=4, Mode=3  →  (0<<6)|(4<<3)|3 = 0x23.
    try testing.expectEqual(@as(u8, 0x23), out[0]);
    // Everything between byte 1 and the transmit timestamp is zero.
    for (out[1..40]) |b| try testing.expectEqual(@as(u8, 0), b);
    // Transmit timestamp (T1) at bytes 40..48, big-endian.
    try testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78 }, out[40..48]);
}

test "encode/decode round-trips a packet" {
    const p: Packet = .{
        .leap = .last_minute_59,
        .version = 4,
        .mode = .server,
        .stratum = 2,
        .poll = 6,
        .precision = -23,
        .root_delay = 0x0001_2345,
        .root_dispersion = 0x0002_3456,
        .reference_id = .{ 'G', 'P', 'S', 0 },
        .reference = .{ .seconds = 1, .fraction = 2 },
        .originate = .{ .seconds = 3, .fraction = 4 },
        .receive = .{ .seconds = 5, .fraction = 6 },
        .transmit = .{ .seconds = 7, .fraction = 8 },
    };
    const bytes = p.encode();
    const q = try Packet.decode(&bytes);
    try testing.expectEqual(p, q);
}

test "decode: parsed header byte splits into LI/VN/Mode" {
    // LI=2 (10), VN=4 (100), Mode=4 (100)  →  10_100_100 = 0xA4.
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0xA4;
    bytes[1] = 3; // stratum
    const p = try Packet.decode(&bytes);
    try testing.expectEqual(LeapIndicator.last_minute_59, p.leap);
    try testing.expectEqual(@as(u3, 4), p.version);
    try testing.expectEqual(Mode.server, p.mode);
    try testing.expectEqual(@as(u8, 3), p.stratum);
}

test "decodeResponse: canned server reply" {
    // A hand-built server response: LI=0 VN=4 Mode=4 (0x24), stratum 2.
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x24;
    bytes[1] = 2; // stratum 2
    bytes[2] = 4; // poll
    bytes[3] = @bitCast(@as(i8, -20)); // precision
    // reference id "GPS\0"
    @memcpy(bytes[12..16], "GPS\x00");
    // receive (T2) = seconds 0x0000_0064, fraction 0.
    std.mem.writeInt(u32, bytes[32..36], 0x0000_0064, .big);
    // transmit (T3) = seconds 0x0000_0065, fraction 0.
    std.mem.writeInt(u32, bytes[40..44], 0x0000_0065, .big);

    const reply = try decodeResponse(&bytes);
    try testing.expectEqual(@as(u8, 2), reply.stratum);
    try testing.expectEqual(Mode.server, reply.mode);
    try testing.expectEqual(@as(i8, -20), reply.precision);
    try testing.expectEqual(@as(u32, 0x64), reply.receive.seconds);
    try testing.expectEqual(@as(u32, 0x65), reply.transmit.seconds);
    try testing.expectEqualSlices(u8, "GPS\x00", &reply.reference_id);
}

test "decodeResponse: rejects wrong length" {
    const short = [_]u8{0} ** 40;
    try testing.expectError(error.InvalidLength, decodeResponse(&short));
    const long = [_]u8{0} ** 56;
    try testing.expectError(error.InvalidLength, decodeResponse(&long));
}

test "decodeResponse: rejects non-server mode" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x23; // mode 3 (client)
    bytes[1] = 2;
    try testing.expectError(error.NotServerMode, decodeResponse(&bytes));
}

test "decodeResponse: stratum 0 is Kiss-o'-Death" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x24; // server mode
    bytes[1] = 0; // stratum 0 → KoD
    @memcpy(bytes[12..16], "RATE");
    try testing.expectError(error.KissOfDeath, decodeResponse(&bytes));
}

test "NTP↔Unix epoch conversion at a known instant" {
    // 2001-09-09T01:46:40Z: Unix seconds = 1_000_000_000, so
    //   NTP seconds = 1_000_000_000 + 2_208_988_800 = 3_208_988_800.
    const unix_secs: u64 = 1_000_000_000;
    const ntp_secs: u32 = @intCast(unix_secs + ntp_unix_offset_s);
    try testing.expectEqual(@as(u32, 3_208_988_800), ntp_secs);

    const ts: Timestamp = .{ .seconds = ntp_secs, .fraction = 0 };
    const unix_ns = ts.toUnixNanos();
    try testing.expectEqual(@as(i128, unix_secs) * std.time.ns_per_s, unix_ns);

    // Round-trip through fromUnixNanos.
    const back = Timestamp.fromUnixNanos(unix_ns);
    try testing.expectEqual(ntp_secs, back.seconds);
    try testing.expectEqual(@as(u32, 0), back.fraction);
}

test "fixed-point fraction ↔ nanoseconds" {
    // fraction 0x8000_0000 = half a second = 500_000_000 ns.
    const half: Timestamp = .{ .seconds = 0, .fraction = 0x8000_0000 };
    try testing.expectEqual(@as(u64, 500_000_000), half.nanosSinceNtpEpoch());

    // Round-trip a whole second plus a quarter.
    const q: Timestamp = .{ .seconds = 1, .fraction = 0x4000_0000 };
    try testing.expectEqual(@as(u64, 1_250_000_000), q.nanosSinceNtpEpoch());
    const rebuilt = Timestamp.fromNanosSinceNtpEpoch(1_250_000_000);
    try testing.expectEqual(@as(u32, 1), rebuilt.seconds);
    try testing.expectEqual(@as(u32, 0x4000_0000), rebuilt.fraction);
}

test "offset + delay against hand-computed T1..T4" {
    // Pick whole-second timestamps so the math is exact.
    //   T1 = 10s, T2 = 20s, T3 = 21s, T4 = 13s   (all fraction 0)
    // offset = ((T2−T1)+(T3−T4))/2 = ((10)+(8))/2 = 9 s
    // delay  = (T4−T1)−(T3−T2)     = (3)−(1)       = 2 s
    const t1: Timestamp = .{ .seconds = 10 };
    const t2: Timestamp = .{ .seconds = 20 };
    const t3: Timestamp = .{ .seconds = 21 };
    const t4: Timestamp = .{ .seconds = 13 };

    const sample: Sample = .{ .originate = t1, .receive = t2, .transmit = t3, .destination = t4 };
    try testing.expectEqual(@as(i128, 9) * std.time.ns_per_s, sample.offsetNanos());
    try testing.expectEqual(@as(i128, 2) * std.time.ns_per_s, sample.roundtripDelayNanos());

    // Free functions agree.
    try testing.expectEqual(sample.offsetNanos(), computeOffsetNanos(t1, t2, t3, t4));
    try testing.expectEqual(sample.roundtripDelayNanos(), computeDelayNanos(t1, t2, t3, t4));
}

test "offset can be negative (local clock ahead)" {
    // Local clock 5s ahead: T1=105, T2=100, T3=101, T4=107.
    // offset = ((100−105)+(101−107))/2 = ((−5)+(−6))/2 = −5.5 s
    const t1: Timestamp = .{ .seconds = 105 };
    const t2: Timestamp = .{ .seconds = 100 };
    const t3: Timestamp = .{ .seconds = 101 };
    const t4: Timestamp = .{ .seconds = 107 };
    const off = computeOffsetNanos(t1, t2, t3, t4);
    try testing.expectEqual(-@as(i128, 5_500_000_000), off);
}

test "nowTimestamp is in a sane modern range" {
    const ts = nowTimestamp();
    // After 2020-01-01 (NTP seconds for 2020 ≈ 3.786e9) and before the
    // era-0 rollover in 2036.
    try testing.expect(ts.seconds > 3_786_825_600);
    try testing.expect(ts.seconds < 4_294_944_000);
}

test "query: live network (skipped offline)" {
    // Gate any real query behind SkipZigTest — no live server in CI.
    return error.SkipZigTest;
}
