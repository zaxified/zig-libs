# sntp

SNTP client (RFC 4330): a pure 48-byte NTP packet **codec** plus a blocking
UDP **query** that reads a public time server and computes the local clock
offset and round-trip delay.

- Std has no NTP/SNTP support at all.
- **Model after:** RFC 4330 (SNTP for IPv4/IPv6); packet layout and the
  T1–T4 offset/delay arithmetic mirror the design of
  [`FObersteiner/ntp_client`](https://codeberg.org/FObersteiner/ntp_client)
  (`src/ntp.zig`, MIT) — a clean-room re-derivation, no code copied.
- **Platform:** any — the wire codec is portable; the local send/receive
  instants come from the libc-free `clock_gettime(REALTIME)` errno form
  (`RtlGetSystemTimePrecise` on Windows), same as the sibling `jwt`/`jobqueue`
  modules. **Role:** client (codec + UDP). **Concurrency:** reentrant (no
  shared state).
- **Deps:** `std.Io.net` (UDP datagram socket for `query`).

Provenance: clean-room from RFC 4330 (SNTPv4) (and RFC 5905 for the timestamp
format) — original work of the zig-libs authors (MIT). The packet layout and
offset/delay *design* are modeled after `FObersteiner/ntp_client` (MIT,
Codeberg); **no third-party code was copied**.

## Epoch & fixed-point model

- NTP timestamps are 64-bit **fixed-point seconds since the NTP epoch
  1900-01-01**: the high 32 bits are whole seconds, the low 32 bits are the
  fraction in units of 1/2^32 second (`Timestamp{ seconds, fraction }`).
  Big-endian on the wire.
- Unix time is `NTP − 2_208_988_800 s` (`ntp_unix_offset_s`).
- `Timestamp` converts both ways: `nanosSinceNtpEpoch`/`fromNanosSinceNtpEpoch`
  (fraction ↔ ns via `frac * 1e9 >> 32` and `ns << 32 / 1e9`) and
  `toUnixNanos`/`fromUnixNanos`. Offset/delay differences are computed in
  **i128 nanoseconds** so they stay exact and can be negative.
- `root_delay` / `root_dispersion` are kept as raw 16.16 "NTP short" fixed
  point; `rootDelaySeconds` / `rootDispersionSeconds` interpret them.

## API

```zig
const sntp = @import("sntp");

// Codec — transport-agnostic, no I/O:
var req: [sntp.packet_len]u8 = undefined;
sntp.encodeRequest(&req, sntp.nowTimestamp());   // client mode, VN 4, T1 set
var kiss: sntp.KissOfDeath = undefined;
const reply = sntp.decodeResponse(bytes, &kiss) catch |err| switch (err) {
    error.KissOfDeath => switch (kiss.code) {
        .rate => { /* back off: increase polling interval */ return err; },
        .deny, .rstr => { /* stop sending to this server */ return err; },
        else => return err,
    },
    else => return err,
};

// Offset & round-trip delay from the four timestamps (nanoseconds):
const sample: sntp.Sample = .{
    .originate = t1, .receive = t2, .transmit = t3, .destination = t4,
};
const offset_ns = sample.offsetNanos();          // ((T2−T1)+(T3−T4))/2
const delay_ns  = sample.roundtripDelayNanos();  // (T4−T1)−(T3−T2)

// One-shot UDP query (IPv4 or IPv6) over std.Io.net:
const server = try std.Io.net.IpAddress.parse("162.159.200.1", sntp.ntp_port);
const r = try sntp.query(io, server, .{ .timeout_ms = 3000 }, null); // null: ignore KoD detail
// r.reply (stratum, timestamps…), r.sample, r.offset_ns, r.roundtrip_ns
```

`decodeResponse(bytes, kiss_out)` returns distinct errors: `InvalidLength` (not 48 bytes),
`InvalidVersion` (VN = 0), `NotServerMode` (mode ≠ 4), `KissOfDeath` (stratum 0 —
pass a non-null `kiss_out: ?*KissOfDeath` to get the parsed `KissCode` and raw
4-byte reason from `reference_id`, per RFC 5905 §7.4), `UnsynchronizedStratum`
(stratum ≥ 16 — RFC 5905: 16 is "unsynchronized", 17-255 reserved), and
`TransmitTimestampUnset` (the server hasn't set its own clock yet). `query`
forwards its own `kiss_out: ?*KissOfDeath` parameter the same way.

**Known limitation — NTP era 0 (until 2036-02-07):** timestamps are decoded as
a bare 32-bit seconds count with no era pivot, so arithmetic is only correct
inside the current NTP era; see SPEC.md for detail. Not fixed here — no
surveyed implementation has actually solved it either.

## Tests

`zig build test-sntp` — offline, no live server: golden request bytes (the
`LI|VN|Mode` byte + T1 placement), packet encode/decode round-trip, a canned
server response (stratum/precision/timestamps/ref-id), the reject paths
(length, version 0, mode, Kiss-o'-Death with its parsed reason code, stratum
≥ 16, an unset Transmit Timestamp), NTP↔Unix epoch conversion at a known
instant, fraction↔nanosecond round-trips, and offset/delay against
hand-computed T1..T4 (including a negative offset). The live `query` test is
gated behind `error.SkipZigTest`.

## Deferred (not in v1)

- Full NTP (RFC 5905): the intersection/clustering/combining algorithms.
- Server side.
- NTP authentication (the optional MAC / extension fields; only the plain
  48-byte packet is parsed — longer packets are rejected as `InvalidLength`).
- Leap-second handling beyond surfacing the `LeapIndicator` flag.
- Multi-server sampling / racing and best-sample selection.
- NTP era 0 rollover (2036-02-07): documented as a known bound, not fixed.
