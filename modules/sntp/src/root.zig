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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "SNTP client (RFC 4330) — NTP packet codec + UDP query, clock offset / round-trip delay",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .linux32 },
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

    /// Exact field equality — used to verify a server reply's `originate`
    /// timestamp echoes the client's own request `transmit` timestamp
    /// (RFC 4330 §5's origin-timestamp check; see `verifyOriginate`).
    pub fn eql(self: Timestamp, other: Timestamp) bool {
        return self.seconds == other.seconds and self.fraction == other.fraction;
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

/// Registered Kiss-o'-Death reason codes (RFC 5905 §7.4, Figure 13 "Kiss
/// Codes"). Sent in `reference_id` when `stratum == 0`.
pub const KissCode = enum {
    /// ACST — the association belongs to a unicast server.
    acst,
    /// AUTH — server authentication failed.
    auth,
    /// AUTO — Autokey sequence failed.
    auto,
    /// BCST — the association belongs to a broadcast server.
    bcst,
    /// CRYP — cryptographic authentication or identification failed.
    cryp,
    /// DENY — access denied by remote server. RFC 5905 §7.4: the client
    /// MUST demobilize any association to that server and stop sending it
    /// packets.
    deny,
    /// DROP — lost peer in symmetric mode.
    drop,
    /// INIT — the association has not yet synchronized for the first time.
    init,
    /// MCST — the association belongs to a dynamically discovered server.
    mcst,
    /// NKEY — no key found; the key was never installed or is not trusted.
    nkey,
    /// RATE — rate exceeded: the server temporarily denied access because
    /// the client exceeded the rate threshold. RFC 5905 §7.4: the client
    /// MUST immediately reduce its polling interval to that server, and
    /// continue reducing it each time RATE is received again.
    rate,
    /// RMOT — alteration of the association from a remote host running
    /// ntpdc.
    rmot,
    /// RSTR — access denied due to local policy. RFC 5905 §7.4: same
    /// mandatory response as `deny` — demobilize and stop sending.
    rstr,
    /// STEP — a step change in system time has occurred, but the
    /// association has not yet resynchronized.
    step,
    /// Not one of the 14 codes above. Covers RFC 5905 §7.4's "X"-prefixed
    /// experimental range ("reserved for unregistered experimentation and
    /// development and MUST be ignored if not recognized") and any other
    /// four-byte value, including non-ASCII bytes — `reference_id` is an
    /// opaque wire field, not guaranteed text from a hostile or buggy peer.
    /// `KissOfDeath.raw` always keeps the original bytes for a caller that
    /// wants to log or re-inspect them.
    unrecognized,
};

/// Parse a raw 4-byte `reference_id` into a `KissCode` per the RFC 5905
/// §7.4 table. Deliberately total (never fails): an unrecognized or
/// malformed value maps to `.unrecognized` rather than an error, matching
/// the RFC's own instruction to ignore codes it doesn't define.
pub fn parseKissCode(raw: [4]u8) KissCode {
    const table = .{
        .{ "ACST", KissCode.acst },
        .{ "AUTH", KissCode.auth },
        .{ "AUTO", KissCode.auto },
        .{ "BCST", KissCode.bcst },
        .{ "CRYP", KissCode.cryp },
        .{ "DENY", KissCode.deny },
        .{ "DROP", KissCode.drop },
        .{ "INIT", KissCode.init },
        .{ "MCST", KissCode.mcst },
        .{ "NKEY", KissCode.nkey },
        .{ "RATE", KissCode.rate },
        .{ "RMOT", KissCode.rmot },
        .{ "RSTR", KissCode.rstr },
        .{ "STEP", KissCode.step },
    };
    inline for (table) |entry| {
        if (std.mem.eql(u8, &raw, entry[0])) return entry[1];
    }
    return .unrecognized;
}

/// A Kiss-o'-Death signal, decoded from a `stratum == 0` reply.
pub const KissOfDeath = struct {
    /// The parsed reason, per `parseKissCode`.
    code: KissCode,
    /// The original 4 ASCII bytes from `reference_id`, kept regardless of
    /// `code` (e.g. to log an `.unrecognized` value).
    raw: [4]u8,
};

/// Errors from validating a server response.
pub const DecodeError = error{
    /// Not exactly 48 bytes.
    InvalidLength,
    /// The reply's version number is 0 (RFC 4330 §5 sanity check 4, as
    /// corrected by RFC Errata 2263 — the published text names the LI
    /// field, but the errata, verified by an RFC 4330 author, confirms the
    /// intended field is VN: "Zero is a legal value for the LI field under
    /// normal conditions. Zero is not legal for [the] VN field").
    InvalidVersion,
    /// The reply is not in server mode (mode 4).
    NotServerMode,
    /// Stratum 0 — a Kiss-o'-Death packet (RFC 4330 §8, RFC 5905 §7.4). Pass
    /// a non-null `kiss_out` to `decodeResponse` to get the parsed reason.
    KissOfDeath,
    /// Stratum 16 or above: RFC 5905 §7.3 Figure 11 defines 16 as
    /// "unsynchronized" and 17-255 as reserved (RFC 4330 §4 calls the whole
    /// 16-255 range simply "reserved"). Neither is a valid, synchronized
    /// time source, so both are rejected the same way.
    UnsynchronizedStratum,
    /// Leap Indicator is `.unsynchronized` (LI = 3, RFC 4330 §4's own "alarm
    /// condition — clock not synchronized"). Audit finding F7: a reply with
    /// stratum >= 16 was already rejected as not a valid synchronized time
    /// source, but a reply saying the identical thing through its LI field
    /// instead was accepted — an inconsistency, not a deliberate leniency
    /// (see SPEC.md threat model).
    UnsynchronizedLeap,
    /// The reply's Transmit Timestamp (T3) is the all-zero sentinel RFC
    /// 4330 uses for "not set" — RFC 4330 §5 sanity check 4 says to discard
    /// such a reply (the server hasn't set its own clock yet).
    TransmitTimestampUnset,
    /// The reply's Receive Timestamp (T2) is the all-zero sentinel. Audit
    /// finding F3: RFC 4330 §5 sanity check 4 applies to T2 exactly like
    /// T3, but only T3 was checked before this. Left open, a server
    /// reporting T2 = 0 sends `query`'s offset computation wherever the
    /// server's T3 puts it, unbounded (measured: an offset of -63 years
    /// from T2 = 0 alone, every other field left honest).
    ReceiveTimestampUnset,
};

/// A validated server reply. Alias of `Packet` — the `originate`/`receive`/
/// `transmit` fields carry T1/T2/T3 respectively.
pub const Reply = Packet;

/// Decode + validate a server response: exactly 48 bytes, a non-zero
/// version, server mode, a stratum in 1..15, a Leap Indicator that isn't
/// `.unsynchronized`, and set (non-zero) Receive and Transmit timestamps —
/// the RFC 4330 §5 sanity-check list (item 4, VN-corrected per Errata 2263)
/// plus RFC 5905's stratum range, plus the LI/T2 checks closed by audit
/// findings F7 and F3 respectively.
///
/// On `error.KissOfDeath` (stratum 0), if `kiss_out` is non-null it is
/// filled in with the parsed reason code and the raw `reference_id` bytes —
/// callers that need to honour RATE (back off) or distinguish DENY/RSTR
/// (stop sending) from anything else don't have to re-decode the packet
/// themselves. Pass `null` to ignore it.
pub fn decodeResponse(bytes: []const u8, kiss_out: ?*KissOfDeath) DecodeError!Reply {
    const p = Packet.decode(bytes) catch return error.InvalidLength;
    if (p.version == 0) return error.InvalidVersion;
    if (p.mode != .server) return error.NotServerMode;
    if (p.stratum == 0) {
        if (kiss_out) |out| out.* = .{ .code = parseKissCode(p.reference_id), .raw = p.reference_id };
        return error.KissOfDeath;
    }
    if (p.stratum >= 16) return error.UnsynchronizedStratum;
    if (p.leap == .unsynchronized) return error.UnsynchronizedLeap;
    if (p.transmit.isZero()) return error.TransmitTimestampUnset;
    if (p.receive.isZero()) return error.ReceiveTimestampUnset;
    return p;
}

/// Verify the RFC 4330 §5 origin-timestamp check: a genuine reply to *our*
/// request must echo back, in `reply.originate`, exactly the `transmit`
/// timestamp (`t1`) we sent. This is the standard anti-spoof/anti-replay
/// defense for unauthenticated SNTP — a blind off-path attacker who can spoof
/// the source address but never observed the 64-bit `t1` we chose cannot
/// forge a reply that passes it. `query` calls this after `decodeResponse`
/// and before trusting the reply; exposed separately so it's testable
/// without a live network exchange.
pub fn verifyOriginate(reply: Reply, t1: Timestamp) error{OriginateMismatch}!void {
    if (!reply.originate.eql(t1)) return error.OriginateMismatch;
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

/// Failure to read the local clock (audit finding F11). Before this, a
/// `clock_gettime` failure made `nowUnixNanos` silently return 0 — the Unix
/// epoch, i.e. NTP timestamp 1900+70 years in the past — and that garbage
/// value would go on to become T1 or T4 with no signal to the caller at all.
/// Fail closed instead: a caller that can't read its own clock can't compute
/// a meaningful offset, and should hear about it.
pub const ClockError = error{ClockUnavailable};

/// The pure error/timespec → nanoseconds step of `nowUnixNanos`'s POSIX
/// branch, split out so it's directly testable without depending on
/// `clock_gettime` actually failing (which it practically never does on
/// Linux — vDSO). Audit finding F11 was "read from code, not reproduced";
/// this is what makes the fail-closed behavior a measured fact instead.
fn unixNanosFromClockResult(errno: std.posix.E, ts: std.posix.timespec) ClockError!i128 {
    if (errno != .SUCCESS) return error.ClockUnavailable;
    return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
}

/// Current wall-clock instant as nanoseconds since the Unix epoch. std's
/// `std.time` timestamp helpers were removed in 0.16; this uses the libc-free
/// `clock_gettime(REALTIME)` errno form (and `RtlGetSystemTimePrecise` on
/// Windows), matching the sibling modules (jwt/jobqueue).
pub fn nowUnixNanos() ClockError!i128 {
    switch (builtin.os.tag) {
        .windows => {
            // 100 ns ticks since 1601-01-01; shift to the Unix epoch, then to ns.
            // RtlGetSystemTimePrecise has no documented failure mode.
            const hns: i64 = std.os.windows.ntdll.RtlGetSystemTimePrecise();
            return @as(i128, hns - 116444736000000000) * 100;
        },
        else => {
            var ts: std.posix.timespec = undefined;
            const errno = std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts));
            return unixNanosFromClockResult(errno, ts);
        },
    }
}

/// Current instant as an NTP `Timestamp`.
pub fn nowTimestamp() ClockError!Timestamp {
    return Timestamp.fromUnixNanos(try nowUnixNanos());
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
    /// The reply's `originate` timestamp does not echo the origin nonce this
    /// `query` sent (see `query`'s origin-nonce comment) — RFC 4330 §5's
    /// origin-timestamp check failed. Either a spoofed/off-path reply or a
    /// badly broken server; reject it either way (see `verifyOriginate`).
    OriginateMismatch,
    /// `std.Io.randomSecure` could not source fresh entropy for the
    /// anti-spoof origin-timestamp nonce (audit finding F4). Fails closed
    /// rather than silently falling back to a predictable nonce — see
    /// `query`'s origin-nonce comment and `modules/entropy`'s doc comment
    /// ("if your signature can return an error, do not use [the
    /// silently-degrading `std.Io.random`] — call `randomSecure` directly
    /// and let the caller decide"), this repo's settled entropy policy.
    EntropyUnavailable,
} || ClockError || DecodeError;

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
///
/// `kiss_out` is forwarded to `decodeResponse` — pass a non-null pointer to
/// learn the Kiss-o'-Death reason on `error.KissOfDeath` (e.g. to back off on
/// RATE), or `null` to ignore it.
pub fn query(io: std.Io, server: net.IpAddress, options: QueryOptions, kiss_out: ?*KissOfDeath) QueryError!QueryResult {
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

    // T1: the real send instant — used for the offset/delay math in
    // `validateReply`, nowhere else.
    const t1 = try nowTimestamp();

    // The wire origin nonce (audit finding F4): a client Transmit Timestamp
    // built only from a wall-clock read is only as unpredictable as the
    // clock's resolution — measured 21-24 bits of an off-path attacker's
    // search space on this host, against `verifyOriginate`'s doc comment
    // claiming all 64. Keep `t1.seconds` (the request still carries a
    // plausible "now") but replace the fraction with 32 fresh bits from
    // `std.Io.randomSecure` — fail-closed, not `std.Io.random`'s weaker,
    // silently degrading seed (see `QueryError.EntropyUnavailable`).
    // `verifyOriginate` below checks the reply against THIS nonce, not
    // `t1` — the offset/delay math uses `t1` itself (see `validateReply`),
    // so randomizing the wire value costs no accuracy.
    var nonce_fraction_bytes: [4]u8 = undefined;
    std.Io.randomSecure(io, &nonce_fraction_bytes) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.EntropyUnavailable => return error.EntropyUnavailable,
    };
    const origin_nonce: Timestamp = .{
        .seconds = t1.seconds,
        .fraction = std.mem.readInt(u32, &nonce_fraction_bytes, .big),
    };

    const req_pkt: Packet = .{ .version = options.version, .mode = .client, .transmit = origin_nonce };
    const request = req_pkt.encode();

    const dest = server;
    sock.send(io, &dest, &request) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.NetworkFailed,
    };

    // Receive the reply. `processReply`/`validateReply` carry BOTH anti-spoof
    // guards (source-address/port match, origin-nonce echo) plus the
    // truncation check — audit finding F1 was that `query`'s own receive
    // loop held its guards in a form no test reached, so a mutation dropping
    // either the peer check or the `verifyOriginate` call left the whole
    // suite green. They now live in functions unit tests call directly; this
    // loop is a thin, largely inert wrapper around them.
    const deadline = deadlineFromMs(io, options.timeout_ms);
    var rbuf: [packet_len]u8 = undefined;
    while (true) {
        const incoming = sock.receiveTimeout(io, &rbuf, deadline) catch |err| switch (err) {
            error.Timeout => return error.Timeout,
            error.Canceled => return error.Canceled,
            else => return error.NetworkFailed,
        };
        const t4 = try nowTimestamp(); // T4: local receive instant.
        const result = processReply(incoming.data, incoming.flags.trunc, incoming.from, dest, origin_nonce, t1, t4, kiss_out) orelse continue;
        return result;
    }
}

/// Validate one received datagram against a pending exchange: reject it
/// unless it's from `server` (else a blind off-path attacker flooding from
/// other ports/addresses could derail the exchange), then hand off to
/// `validateReply`. Split out of `query`'s receive loop so this — the whole
/// point of the peer-address guard — is directly unit-testable without a
/// socket (audit finding F1).
///
/// Returns `null` when `from` doesn't match `server` — the caller's receive
/// loop should keep waiting, not fail the query.
fn processReply(
    data: []const u8,
    truncated: bool,
    from: net.IpAddress,
    server: net.IpAddress,
    origin_nonce: Timestamp,
    t1: Timestamp,
    t4: Timestamp,
    kiss_out: ?*KissOfDeath,
) ?QueryError!QueryResult {
    if (!from.eql(&server)) return null;
    return validateReply(data, truncated, origin_nonce, t1, t4, kiss_out);
}

/// The truncation / decode / origin-echo checks and `QueryResult` build,
/// split out of `processReply` so a test can drive it with a canned
/// already-matched-peer datagram without constructing a `net.IpAddress`.
fn validateReply(
    data: []const u8,
    truncated: bool,
    origin_nonce: Timestamp,
    t1: Timestamp,
    t4: Timestamp,
    kiss_out: ?*KissOfDeath,
) QueryError!QueryResult {
    // A truncated read means the real datagram was longer than
    // `packet_len` — README/SPEC both promise those are rejected as
    // `InvalidLength`, but nothing enforced it (audit finding F2): the
    // kernel silently hands back exactly `packet_len` bytes either way, and
    // only `incoming.flags.trunc` tells the two cases apart.
    if (truncated) return error.InvalidLength;
    const reply = try decodeResponse(data, kiss_out);
    // RFC 4330 §5 origin-timestamp check: reject unless the reply echoes
    // back the nonce this exchange sent. Must happen before the reply is
    // trusted for anything else (offset/delay computation below).
    try verifyOriginate(reply, origin_nonce);
    const sample: Sample = .{
        .originate = t1, // the real T1 clock reading, NOT the wire nonce
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

    const reply = try decodeResponse(&bytes, null);
    try testing.expectEqual(@as(u8, 2), reply.stratum);
    try testing.expectEqual(Mode.server, reply.mode);
    try testing.expectEqual(@as(i8, -20), reply.precision);
    try testing.expectEqual(@as(u32, 0x64), reply.receive.seconds);
    try testing.expectEqual(@as(u32, 0x65), reply.transmit.seconds);
    try testing.expectEqualSlices(u8, "GPS\x00", &reply.reference_id);
}

test "decodeResponse: rejects wrong length" {
    const short = [_]u8{0} ** 40;
    try testing.expectError(error.InvalidLength, decodeResponse(&short, null));
    const long = [_]u8{0} ** 56;
    try testing.expectError(error.InvalidLength, decodeResponse(&long, null));
}

test "decodeResponse: rejects non-server mode" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x23; // mode 3 (client)
    bytes[1] = 2;
    try testing.expectError(error.NotServerMode, decodeResponse(&bytes, null));
}

test "decodeResponse: rejects version 0 (RFC 4330 §5 item 4, VN per Errata 2263)" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x04; // LI=0, VN=0, Mode=4 (server)
    bytes[1] = 2; // stratum 2
    std.mem.writeInt(u32, bytes[40..44], 1, .big); // non-zero transmit, isolates the VN check
    try testing.expectError(error.InvalidVersion, decodeResponse(&bytes, null));
}

test "decodeResponse: stratum 16 and above is UnsynchronizedStratum" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x24; // VN=4, server mode
    std.mem.writeInt(u32, bytes[40..44], 1, .big); // non-zero transmit
    bytes[1] = 16;
    try testing.expectError(error.UnsynchronizedStratum, decodeResponse(&bytes, null));
    bytes[1] = 255;
    try testing.expectError(error.UnsynchronizedStratum, decodeResponse(&bytes, null));
}

test "decodeResponse: stratum 15 (top of the valid secondary-reference range) is accepted" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x24; // VN=4, server mode
    bytes[1] = 15;
    std.mem.writeInt(u32, bytes[32..36], 1, .big); // non-zero receive (F3)
    std.mem.writeInt(u32, bytes[40..44], 1, .big); // non-zero transmit
    const reply = try decodeResponse(&bytes, null);
    try testing.expectEqual(@as(u8, 15), reply.stratum);
}

test "decodeResponse: rejects an all-zero Transmit Timestamp (RFC 4330 §5 item 4)" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x24; // VN=4, server mode
    bytes[1] = 2; // stratum 2, well clear of KissOfDeath/UnsynchronizedStratum
    // bytes[40..48] (transmit) left all-zero; receive left all-zero too, but
    // the transmit check runs first so it's TransmitTimestampUnset that fires.
    try testing.expectError(error.TransmitTimestampUnset, decodeResponse(&bytes, null));
}

test "decodeResponse: rejects an all-zero Receive Timestamp (audit finding F3)" {
    // Reproduces the audit's finding: a server echoing T1 correctly but
    // reporting T2 = 0 passed every check before this and drove `query`'s
    // offset to -63 years (measured against a live stub). transmit is set
    // so only the new T2 check is isolated.
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x24; // VN=4, server mode
    bytes[1] = 2; // stratum 2
    std.mem.writeInt(u32, bytes[40..44], 1, .big); // non-zero transmit
    // bytes[32..40] (receive) left all-zero.
    try testing.expectError(error.ReceiveTimestampUnset, decodeResponse(&bytes, null));
}

test "decodeResponse: rejects Leap Indicator 3 (unsynchronized), a KoD-shaped stratum aside (audit finding F7)" {
    // LI=3 (11), VN=4 (100), Mode=4 (100)  ->  11_100_100 = 0xE4.
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0xE4;
    bytes[1] = 2; // stratum 2, clear of KissOfDeath/UnsynchronizedStratum
    std.mem.writeInt(u32, bytes[32..36], 1, .big); // non-zero receive
    std.mem.writeInt(u32, bytes[40..44], 1, .big); // non-zero transmit
    try testing.expectError(error.UnsynchronizedLeap, decodeResponse(&bytes, null));
}

test "decodeResponse: LI 0-2 (not the alarm value) still accepted, isolating F7's check" {
    inline for ([_]LeapIndicator{ .no_warning, .last_minute_61, .last_minute_59 }) |li| {
        var bytes = [_]u8{0} ** packet_len;
        bytes[0] = (@as(u8, @intFromEnum(li)) << 6) | (4 << 3) | 4; // LI | VN=4 | Mode=4
        bytes[1] = 2;
        std.mem.writeInt(u32, bytes[32..36], 1, .big);
        std.mem.writeInt(u32, bytes[40..44], 1, .big);
        const reply = try decodeResponse(&bytes, null);
        try testing.expectEqual(li, reply.leap);
    }
}

test "decodeResponse: stratum 0 is Kiss-o'-Death" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x24; // server mode
    bytes[1] = 0; // stratum 0 → KoD
    @memcpy(bytes[12..16], "RATE");
    try testing.expectError(error.KissOfDeath, decodeResponse(&bytes, null));
}

test "decodeResponse: surfaces the parsed Kiss-o'-Death code and raw bytes via kiss_out" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x24; // server mode
    bytes[1] = 0; // stratum 0 → KoD
    @memcpy(bytes[12..16], "RATE");

    var kod: KissOfDeath = undefined;
    try testing.expectError(error.KissOfDeath, decodeResponse(&bytes, &kod));
    try testing.expectEqual(KissCode.rate, kod.code);
    try testing.expectEqualSlices(u8, "RATE", &kod.raw);
}

test "decodeResponse: an unregistered/malformed kiss code maps to .unrecognized, not an error" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 0x24;
    bytes[1] = 0;
    @memcpy(bytes[12..16], "XABC"); // RFC 5905 §7.4: "X"-prefixed experimental range

    var kod: KissOfDeath = undefined;
    try testing.expectError(error.KissOfDeath, decodeResponse(&bytes, &kod));
    try testing.expectEqual(KissCode.unrecognized, kod.code);
    try testing.expectEqualSlices(u8, "XABC", &kod.raw);

    // A genuinely malformed (non-ASCII) value is likewise `.unrecognized`,
    // never a decode failure — decodeResponse must not panic on it either.
    bytes[12] = 0xFF;
    bytes[13] = 0x00;
    bytes[14] = 0x01;
    bytes[15] = 0xFE;
    try testing.expectError(error.KissOfDeath, decodeResponse(&bytes, &kod));
    try testing.expectEqual(KissCode.unrecognized, kod.code);
}

test "parseKissCode: covers every RFC 5905 §7.4 registered code" {
    const cases = [_]struct { raw: *const [4]u8, code: KissCode }{
        .{ .raw = "ACST", .code = .acst },
        .{ .raw = "AUTH", .code = .auth },
        .{ .raw = "AUTO", .code = .auto },
        .{ .raw = "BCST", .code = .bcst },
        .{ .raw = "CRYP", .code = .cryp },
        .{ .raw = "DENY", .code = .deny },
        .{ .raw = "DROP", .code = .drop },
        .{ .raw = "INIT", .code = .init },
        .{ .raw = "MCST", .code = .mcst },
        .{ .raw = "NKEY", .code = .nkey },
        .{ .raw = "RATE", .code = .rate },
        .{ .raw = "RMOT", .code = .rmot },
        .{ .raw = "RSTR", .code = .rstr },
        .{ .raw = "STEP", .code = .step },
    };
    for (cases) |c| {
        try testing.expectEqual(c.code, parseKissCode(c.raw.*));
    }
    // DENY and RSTR are the two distinct "must stop sending" codes — the
    // whole reason this module can no longer conflate them behind one
    // opaque error.
    try testing.expect(parseKissCode("DENY".*) != parseKissCode("RSTR".*));
}

test "verifyOriginate: rejects a reply whose originate != t1 (off-path spoof defense)" {
    // Reproduces the audit's finding: `query` never checked this, so a
    // blind off-path attacker who spoofed the source address (but never
    // observed our T1) could get an arbitrary reply accepted.
    const t1: Timestamp = .{ .seconds = 3_900_000_000, .fraction = 0x1234_5678 };
    const forged: Reply = .{
        .mode = .server,
        .stratum = 2,
        .originate = .{ .seconds = t1.seconds, .fraction = t1.fraction +% 1 }, // off by one
    };
    try testing.expectError(error.OriginateMismatch, verifyOriginate(forged, t1));

    const wrong_seconds: Reply = .{
        .mode = .server,
        .stratum = 2,
        .originate = .{ .seconds = t1.seconds +% 1, .fraction = t1.fraction },
    };
    try testing.expectError(error.OriginateMismatch, verifyOriginate(wrong_seconds, t1));

    // All-zero originate (a well-formed-but-nonsensical reply, F3) is also
    // rejected as long as t1 itself isn't the all-zero timestamp.
    const zero_originate: Reply = .{ .mode = .server, .stratum = 2 };
    try testing.expectError(error.OriginateMismatch, verifyOriginate(zero_originate, t1));
}

test "verifyOriginate: accepts a reply that correctly echoes t1" {
    const t1: Timestamp = .{ .seconds = 3_900_000_000, .fraction = 0x1234_5678 };
    const honest: Reply = .{ .mode = .server, .stratum = 2, .originate = t1 };
    try verifyOriginate(honest, t1);
}

test "Timestamp.eql" {
    const a: Timestamp = .{ .seconds = 1, .fraction = 2 };
    const b: Timestamp = .{ .seconds = 1, .fraction = 2 };
    const c: Timestamp = .{ .seconds = 1, .fraction = 3 };
    const d: Timestamp = .{ .seconds = 2, .fraction = 2 };
    try testing.expect(a.eql(b));
    try testing.expect(!a.eql(c));
    try testing.expect(!a.eql(d));
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

test "fromUnixNanos clamps to zero at (and just past) the pre-1900 boundary" {
    // Exactly at the NTP epoch (unix_ns = -ntp_unix_offset_ns): ntp_ns == 0,
    // which the <=0 clamp catches — must not underflow into fromNanosSinceNtpEpoch.
    try testing.expectEqual(Timestamp.zero, Timestamp.fromUnixNanos(-ntp_unix_offset_ns));
    // A moment before 1900: still clamped.
    try testing.expectEqual(Timestamp.zero, Timestamp.fromUnixNanos(-ntp_unix_offset_ns - 5));
    // One second after the epoch: no longer clamped, decodes normally.
    const just_after = Timestamp.fromUnixNanos(-ntp_unix_offset_ns + std.time.ns_per_s);
    try testing.expectEqual(@as(u32, 1), just_after.seconds);
    try testing.expectEqual(@as(u32, 0), just_after.fraction);
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

test "offset rounding direction is pinned to truncation, not floor (audit finding F10)" {
    // Every other offset test in this file sums to an EVEN nanosecond count,
    // so `@divTrunc` and `@divFloor` agree on the whole file except here —
    // `M12` (audit repro) swapped `computeOffsetNanos` from `@divTrunc` to
    // `@divFloor` and the rest of the suite stayed green. `t1`/`t2` are
    // identical (a = 0); `t4`'s fraction is the smallest value whose
    // ns-conversion rounds to an odd nanosecond (1 ns, per
    // `nanosSinceNtpEpoch`'s `>> 32`), so b = -1 ns and the sum is the
    // smallest negative odd number possible: trunc(-1/2) = 0, floor(-1/2) =
    // -1 — the two diverge on this input and only this shape of input.
    const t1: Timestamp = .{ .seconds = 0, .fraction = 0 };
    const t2: Timestamp = .{ .seconds = 0, .fraction = 0 }; // a = t2 - t1 = 0
    const t3: Timestamp = .{ .seconds = 0, .fraction = 0 };
    const t4: Timestamp = .{ .seconds = 0, .fraction = 5 }; // frac_ns(5) = 1, so b = -1
    try testing.expectEqual(@as(u64, 1), t4.nanosSinceNtpEpoch()); // pin the odd-ns setup itself
    const off = computeOffsetNanos(t1, t2, t3, t4);
    try testing.expectEqual(@as(i128, 0), off); // trunc(-1/2) == 0; floor(-1/2) == -1
}

test "nowTimestamp is in a sane modern range" {
    const ts = try nowTimestamp();
    // After 2020-01-01 (NTP seconds for 2020 ≈ 3.786e9) and before the
    // era-0 rollover in 2036.
    try testing.expect(ts.seconds > 3_786_825_600);
    try testing.expect(ts.seconds < 4_294_944_000);
}

test "query: live network (skipped offline)" {
    // Gate any real query behind SkipZigTest — no live server in CI.
    return error.SkipZigTest;
}

// ── audit finding F11: clock failure fails closed, not silently to 1970 ────

test "unixNanosFromClockResult: converts a successful read the same way the old code did" {
    const ts: std.posix.timespec = .{ .sec = 5, .nsec = 250_000_000 };
    try testing.expectEqual(@as(i128, 5_250_000_000), try unixNanosFromClockResult(.SUCCESS, ts));
}

test "unixNanosFromClockResult: fails closed instead of silently returning epoch-zero (audit finding F11)" {
    // Before this fix, a non-SUCCESS errno fell through to `return 0` —
    // Unix epoch, i.e. 70+ years in the past — with no signal to the
    // caller. `ts` is deliberately non-zero garbage to prove the error path
    // doesn't just happen to look right because the timespec was empty.
    const garbage_ts: std.posix.timespec = .{ .sec = 999_999, .nsec = 999_999_999 };
    try testing.expectError(error.ClockUnavailable, unixNanosFromClockResult(.INVAL, garbage_ts));
}

// ── audit findings F1/F2/F4: query's guards, unit-tested without a socket ──

const sntp_test_port: u16 = 123;

fn cannedReply(originate: Timestamp) Packet {
    return .{
        .mode = .server,
        .stratum = 2,
        .originate = originate,
        .receive = .{ .seconds = 100, .fraction = 0x4000_0000 },
        .transmit = .{ .seconds = 100, .fraction = 0x8000_0000 },
    };
}

test "validateReply: accepts a matching reply and uses the real T1, not the wire nonce, for offset math (F4)" {
    // origin_nonce is what's on the wire and gets echo-checked; t1 is the
    // real clock reading `query` captured and is what should end up in
    // `sample.originate`. They're deliberately different values here.
    const origin_nonce: Timestamp = .{ .seconds = 100, .fraction = 0xAAAA_AAAA };
    const t1: Timestamp = .{ .seconds = 100, .fraction = 0x1111_1111 };
    const t4: Timestamp = .{ .seconds = 101, .fraction = 0 };
    const bytes = cannedReply(origin_nonce).encode();

    const result = try validateReply(&bytes, false, origin_nonce, t1, t4, null);
    try testing.expectEqual(t1, result.sample.originate);
    try testing.expect(!t1.eql(origin_nonce));
}

test "validateReply: rejects a reply that doesn't echo the origin nonce (F1's verifyOriginate guard, unit-tested directly)" {
    const origin_nonce: Timestamp = .{ .seconds = 100, .fraction = 1 };
    const wrong_echo: Timestamp = .{ .seconds = 100, .fraction = 2 };
    const t1 = origin_nonce;
    const t4: Timestamp = .{ .seconds = 101 };
    const bytes = cannedReply(wrong_echo).encode();
    try testing.expectError(error.OriginateMismatch, validateReply(&bytes, false, origin_nonce, t1, t4, null));
}

test "validateReply: rejects a truncated datagram even though the buffer holds exactly packet_len bytes (audit finding F2)" {
    // The kernel truncates an oversized UDP datagram down to the buffer
    // size and signals it via a flag, not a shorter `data.len` — the ONLY
    // way to tell a real 48-byte packet from a truncated bigger one apart
    // is `truncated`. Bytes here are a perfectly well-formed 48-byte reply.
    const origin_nonce: Timestamp = .{ .seconds = 100, .fraction = 1 };
    const t1 = origin_nonce;
    const t4: Timestamp = .{ .seconds = 101 };
    const bytes = cannedReply(origin_nonce).encode();
    try testing.expectError(error.InvalidLength, validateReply(&bytes, true, origin_nonce, t1, t4, null));
}

test "processReply: ignores a datagram from the wrong peer instead of failing the query (F1's peer guard, unit-tested directly)" {
    const server = try net.IpAddress.parse("203.0.113.1", sntp_test_port);
    const attacker = try net.IpAddress.parse("203.0.113.66", sntp_test_port);
    const origin_nonce: Timestamp = .{ .seconds = 100, .fraction = 1 };
    const t1 = origin_nonce;
    const t4: Timestamp = .{ .seconds = 101 };
    const bytes = cannedReply(origin_nonce).encode();
    try testing.expect(processReply(&bytes, false, attacker, server, origin_nonce, t1, t4, null) == null);
}

test "processReply: a matching peer reaches validation and can succeed" {
    const server = try net.IpAddress.parse("203.0.113.1", sntp_test_port);
    const origin_nonce: Timestamp = .{ .seconds = 100, .fraction = 1 };
    const t1 = origin_nonce;
    const t4: Timestamp = .{ .seconds = 101 };
    const bytes = cannedReply(origin_nonce).encode();
    const maybe_result = processReply(&bytes, false, server, server, origin_nonce, t1, t4, null);
    try testing.expect(maybe_result != null);
    _ = try maybe_result.?;
}

// ── golden: one real SNTP exchange, captured once ───────────────────────────
//
// Every packet in every test above is built by hand from this module's own
// field constants (LI/VN/Mode spelled out per RFC 4330, timestamps chosen as
// small round numbers for arithmetic convenience) — a bug that is consistent
// between what this module *encodes* and what it *decodes* (e.g. a field
// swapped the same way on both sides) would still pass every one of them.
// These 48 bytes did NOT come from this module: they are the real reply from
// the public `time.google.com` NTP service (216.239.35.4:123, stratum-1,
// reference id "GOOG") to a genuine SNTP client-mode request, captured once
// with a throwaway UDP client and frozen here (2026-08-01). `t1` below is the
// timestamp that request actually sent (also captured), so `verifyOriginate`
// is exercised against a real echoed value, not a hand-typed one.
//
// Exempt from a NOTICE entry under root NOTICE §0: querying a public server
// once and freezing its bytes is exercising a black-box protocol oracle, the
// same category as running an installed third-party binary (`tar`, `icmp`'s
// live ping) — no source or design was consulted, only wire bytes RFC 4330
// already requires the server to produce.
test "golden: real SNTP reply captured from time.google.com, frozen" {
    const t1: Timestamp = .{ .seconds = 3_994_581_532, .fraction = 0xEF6B2800 };

    const captured_reply = [_]u8{
        0x24, 0x01, 0x00, 0xec, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x07, 0x47, 0x4f, 0x4f, 0x47,
        0xee, 0x18, 0x7a, 0x1c, 0xf6, 0x98, 0x9f, 0x83,
        0xee, 0x18, 0x7a, 0x1c, 0xef, 0x6b, 0x28, 0x00,
        0xee, 0x18, 0x7a, 0x1c, 0xf6, 0x98, 0x9f, 0x84,
        0xee, 0x18, 0x7a, 0x1c, 0xf6, 0x98, 0x9f, 0x86,
    };

    const reply = try decodeResponse(&captured_reply, null);
    try testing.expectEqual(LeapIndicator.no_warning, reply.leap);
    try testing.expectEqual(@as(u3, 4), reply.version);
    try testing.expectEqual(Mode.server, reply.mode);
    try testing.expectEqual(@as(u8, 1), reply.stratum); // primary (GNSS-disciplined) reference
    try testing.expectEqual(@as(i8, 0), reply.poll);
    try testing.expectEqual(@as(i8, -20), reply.precision);
    try testing.expectEqual(@as(u32, 0), reply.root_delay);
    try testing.expectEqual(@as(u32, 7), reply.root_dispersion);
    try testing.expectEqual(@as(f64, 7.0 / 65536.0), reply.rootDispersionSeconds());
    try testing.expectEqualSlices(u8, "GOOG", &reply.reference_id);

    try testing.expectEqual(@as(u32, 3_994_581_532), reply.reference.seconds);
    try testing.expectEqual(@as(u32, 0xF6989F83), reply.reference.fraction);
    try testing.expectEqual(t1, reply.originate); // RFC 4330 §5 origin-timestamp echo
    try testing.expectEqual(@as(u32, 3_994_581_532), reply.receive.seconds);
    try testing.expectEqual(@as(u32, 0xF6989F84), reply.receive.fraction);
    try testing.expectEqual(@as(u32, 3_994_581_532), reply.transmit.seconds);
    try testing.expectEqual(@as(u32, 0xF6989F86), reply.transmit.fraction);

    try verifyOriginate(reply, t1);

    // T4 (this client's local receive instant) is likewise a captured value
    // from the same one-shot exchange — NOT `nowUnixNanos()`. Pinning it as a
    // literal constant is deliberate: an offset/delay assertion computed
    // against the live wall clock would start failing on its own the moment
    // the clock moves on, which is exactly the trap this golden must avoid.
    const t4: Timestamp = .{ .seconds = 3_994_581_532, .fraction = 0xF9AC1000 };
    const sample: Sample = .{
        .originate = reply.originate,
        .receive = reply.receive,
        .transmit = reply.transmit,
        .destination = t4,
    };
    try testing.expectEqual(@as(i128, 8_011_074), sample.offsetNanos());
    try testing.expectEqual(@as(i128, 40_052_890), sample.roundtripDelayNanos());
}

// ── fuzz: server response decode off the wire, never panics ────────────────
//
// `decodeResponse` (and `verifyOriginate` behind it) is what a client runs on
// a UDP datagram from a server it asked nothing more of than its address —
// no auth, no length-agility (fixed 48 bytes), so an off-length or
// off-nominal-field datagram must fail cleanly, not panic. Vary the length
// across and away from the fixed 48 so both `error.InvalidLength` and the
// full field decode are exercised.

/// `testkit.fuzz.seedHex`: a corpus entry is NOT the datagram. `Smith.slice`
/// reads a little-endian `u32` length first, so a raw 48-octet packet handed
/// to the corpus would arrive at the decoder minus its own first four octets.
const seed = @import("testkit").fuzz.seedHex;

/// Server datagrams in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// Every one of these is 48 octets — `packet_len` — except the two that exist
/// to reach `error.InvalidLength`, because the fixed length is the FIRST thing
/// `decodeResponse` checks and uniform random octets clear nothing behind it:
/// a random 48-octet datagram carries mode 4 with probability 1/8 and a
/// version in 1..4 with probability 1/2, so the harness on its own proves only
/// that the length and mode checks reject noise. Lifted from the value tests
/// above; the comment on each names the branch it reaches.
const decode_seeds = [_][]const u8{
    // The captured pool reply from the "golden exchange" test: accepted.
    seed("240100EC0000000000000007474F4F47EE187A1CF6989F83EE187A1CEF6B2800EE187A1CF6989F84EE187A1CF6989F86"),
    // The canned reply: LI=0 VN=4 Mode=4, stratum 2, ref id "GPS\0". Accepted.
    seed("240204EC0000000000000000475053000000000000000000000000000000000000000064000000000000006500000000"),
    seed("00" ** 40), // InvalidLength: 40 octets
    seed("00" ** 56), // InvalidLength: 56 octets
    // NotServerMode: 0x23 is mode 3 (client).
    seed("230200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    // InvalidVersion: VN=0 with a non-zero transmit, so the VN check is what fires.
    seed("040200000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000"),
    // UnsynchronizedStratum: stratum 16.
    seed("241000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000"),
    // Stratum 15, the top of the valid secondary-reference range: accepted.
    // Both receive and transmit set non-zero (F3 added a receive check).
    seed("240F00000000000000000000000000000000000000000000000000000000000000000001000000000000000100000000"),
    // TransmitTimestampUnset: everything else valid, transmit left all-zero.
    seed("240200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    // ReceiveTimestampUnset (audit finding F3): transmit set, receive left all-zero.
    seed("240200000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000"),
    // UnsynchronizedLeap (audit finding F7): LI=3, receive+transmit both set
    // so only the leap check is isolated.
    seed("E40200000000000000000000000000000000000000000000000000000000000000000001000000000000000100000000"),
    // KissOfDeath with a registered code, which is what writes `kiss_out`.
    seed("240000000000000000000000524154450000000000000000000000000000000000000000000000000000000000000000"),
    // KissOfDeath with an unregistered code → `.unrecognized`, not an error.
    seed("240000000000000000000000FF005A5A0000000000000000000000000000000000000000000000000000000000000000"),
};

test "fuzz: decodeResponse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeResponse, .{ .corpus = &decode_seeds });
}

fn fuzzDecodeResponse(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 for every input and `decodeResponse` was called with
    // `buf[0..0]`, dying at `error.InvalidLength` before it ever read a field,
    // with the datagram sitting unread in `buf`. Measured 2026-09-07 over the
    // corpus above: **0 of 11 seeds non-empty and 0 decoded before, 11 of 11
    // non-empty and 3 decoded after.**
    const len: usize = smith.slice(&buf);

    // Always pass a live kiss_out so the KissOfDeath write path (new in this
    // sweep) is exercised by the same never-panics fuzz target, not just the
    // main decode path.
    var kod: KissOfDeath = undefined;
    const reply = decodeResponse(buf[0..len], &kod) catch return;
    verifyOriginate(reply, reply.originate) catch return;
}

test "corpus: every seed reaches decodeResponse, and the accepted count is pinned" {
    // ⭐ The measurement, executable rather than written in a comment. It holds
    // two things nothing else does: a seed longer than the harness's buffer
    // reads back EMPTY (`Smith.slice` falls back to the range minimum), which
    // is silent everywhere else; and a corpus that accepts nothing exercises
    // only the refusal path. `accepted > 0` would be a weak guard here — but
    // `error.InvalidLength` is NOT reachable from the empty input alone, so the
    // second number below is the one the collapsed harness could never produce.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var wrong_length: usize = 0;
    var kissed: usize = 0;
    for (decode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [64]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var kod: KissOfDeath = undefined;
        if (decodeResponse(buf[0..len], &kod)) |_| {
            accepted += 1;
        } else |err| switch (err) {
            error.InvalidLength => wrong_length += 1,
            error.KissOfDeath => kissed += 1,
            else => {},
        }
    }
    try testing.expectEqual(decode_seeds.len, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 of 11 non-empty, 0
    // accepted and 11 of 11 `InvalidLength` from the SAME empty slice. After:
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(@as(usize, 2), wrong_length);
    try testing.expectEqual(@as(usize, 2), kissed);
}
