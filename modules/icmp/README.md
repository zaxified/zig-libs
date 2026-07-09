# icmp

ICMP echo (**ping**) engine: pure ICMPv4/v6 **echo codec**, unprivileged/raw
**ICMP sockets**, and a paced multi-target **Pinger** built for monitoring
workloads (thousands of host checks per cycle).

- **Status:** `extract` — derived from fping's icmp/socket/pinger logic
  (netaddr was the first carve-out from the same lineage).
- **Model after:** fping (schweikert/fping) `main_loop` — plus scaling
  additions (binary-heap scheduling, in-flight cap, per-subnet spacing,
  first-probe jitter, sendmmsg/recvmmsg).
- **Why:** no small pure-Zig ICMP library exists; std has no ICMP support.
- **Platform:** linux (raw errno-encoded `std.os.linux` syscalls, no libc —
  conscious ceiling per BRIEF). **Role:** client. **Concurrency:**
  single_owner (one thread/loop owns a `Pinger`; `stop()` is
  async-signal-safe).
- **Deps:** `seqmap` (reply correlation), `netaddr` (address parse/format).

Provenance: derived from fping (schweikert/fping) — the required fping/
Stanford attribution is in the repository `NOTICE`. Wire formats per RFC 792
(ICMP), RFC 4443 (ICMPv6), RFC 1071 (internet checksum).

## API

```zig
const icmp = @import("icmp");

// The engine — fping as a library.
var pinger = try icmp.Pinger.init(gpa, .{
    .mode = .count,                      // .alive (default) | .count | .loop
    .count = 3,
    .interval_ns = 5 * std.time.ns_per_ms, // global pacing (fping -i)
    .timeout_ns = 500 * std.time.ns_per_ms,
    .max_inflight = 4096,                // hard cap, must stay < 65536
});
defer pinger.deinit();

const id = try pinger.addTarget("192.0.2.1");   // numeric v4/v6 (+ "%zone")
_ = try pinger.addTargetIp(some_netaddr_ip);    // straight from `dns`
pinger.setResultCallback(ctx, onOutcome);       // per-probe reply/timeout/dup
try pinger.run();                                // or prepare()/step()/pollFds()
const st = pinger.stats(id);                     // sent/recv/loss, min/avg/max RTT

// The codec — pure, no I/O.
var pkt: [icmp.echo.echo_header_len + 56]u8 = @splat(0);
icmp.echo.writeEchoRequest(.v4, &pkt, ident, seq); // checksum filled for v4
const reply = icmp.echo.parseV4(bytes, strip_ip_header); // .echo_reply | .icmp_error | .ignored

// The socket — DGRAM-first with RAW fallback.
var sock = try icmp.Socket.open(.v4, .auto, .{});
defer sock.close();
```

## Behavior notes (fping semantics, ported faithfully)

- **Sockets:** unprivileged `SOCK_DGRAM` + `IPPROTO_ICMP`/`ICMPV6` first
  (works when `net.ipv4.ping_group_range` covers the process group), fall back
  to `SOCK_RAW` (needs CAP_NET_RAW/root). Batched sends via `sendmmsg` (only
  forms batches when `interval_ns == 0`), batched receives via `recvmmsg`;
  kernel `SO_TIMESTAMPNS` receive timestamps for accurate RTT under load.
- **Pacing:** a global minimum gap between any two packets (`interval_ns`,
  fping -i), a per-target gap (`perhost_interval_ns`, -p), an in-flight cap,
  optional per-subnet spacing (/24 v4, /64 v6) and first-probe jitter.
- **Modes:** `.alive` stops a target at its first reply and retries timeouts
  with backoff (fping default); `.count` sends exactly N probes (-c); `.loop`
  runs until `stop()` (-l).
- **Replies:** correlated via `seqmap`; late duplicates are counted while the
  answered slot's timeout event is still queued; ICMP errors (unreachable,
  time exceeded) are counted but the probe still resolves via timeout — all
  matching fping's observable behavior.
- The IPv6 echo checksum is left zero — the kernel fills it (it owns the
  pseudo-header) for both DGRAM and RAW ICMPv6 sockets.
- Extras carried over: ICMP timestamp probes (RFC 792, v4-only), TTL/TOS
  set + report, don't-fragment, fwmark, interface bind / outgoing-interface
  pktinfo, source binding, source-address checking.

## Tests

Offline: checksum goldens (RFC 1071 vector + wire-byte goldens v4/v6, comptime
+ property variants), build→parse round trips, error-quote parsing, fuzzed
parsers (never panic on garbage), scheduler/pacing units, seqmap correlation.
Integration (skipped via `error.SkipZigTest` when no ICMP socket can be
opened): pings `127.0.0.1` and `::1` end-to-end and asserts a correlated
reply with a plausible RTT.
