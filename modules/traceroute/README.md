# traceroute

ICMP-echo path discovery: TTL-stepped probes → per-hop addresses + RTTs.
The classic method — ICMP Echo Requests with increasing IP TTL; each router
that expires the TTL answers Time Exceeded (its source address = that hop),
the destination answers Echo Reply (path complete), a Destination
Unreachable terminates the trace with its code recorded. Responses are
correlated to their probe via the echo ident + sequence quoted inside the
ICMP error, so late answers still land in the right hop slot.

- No pure-Zig traceroute engine exists.
- **Platform:** linux — the live path is a raw ICMP socket (`icmp.Socket`,
  CAP_NET_RAW) with per-probe `IP_TTL` / `IPV6_UNICAST_HOPS`; the hop state
  machine itself is pure and runs behind an injectable `Transport` seam.
- **Model after:** traceroute(8) / mtr ICMP method.
- **Deps:** `icmp` (echo codec + error parsing + raw socket), `netaddr`
  (address type/parse/format), `latency-stats` (per-hop min/avg/max/loss).

Result model: `Trace { hops, reached, unreachable_code, dest }`;
`Hop { ttl, probes }` with `stats()` (via latency-stats) and
`distinctAddresses()` (load-balanced hops answer from more than one
address); `Probe { kind: reply|time_exceeded|dest_unreachable|timeout,
address, rtt_ns, code }` — a `timeout` probe is traceroute's `*`.

```zig
const traceroute = @import("traceroute");
const netaddr = @import("netaddr");

const dest = netaddr.parseIp("192.0.2.1").?;
var tr = try traceroute.trace(gpa, dest, .{
    .max_hops = 30,
    .probes_per_hop = 3,
    .timeout_ms = 1000,
});
defer tr.deinit(gpa);
for (tr.hops) |hop| {
    const st = hop.stats(); // min/avg/max RTT, loss %
    _ = st;
}
```

Tests are offline-first: the hop state machine runs against a fake
transport feeding canned ICMP response bytes (Time Exceeded, Echo Reply,
Destination Unreachable, drops, late replies, load-balanced hops, malformed
input) through the real `icmp.echo` parsers on a deterministic virtual
clock. One live test (trace to 127.0.0.1) runs only when CAP_NET_RAW is
available and skips otherwise.

Provenance: original work of the zig-libs authors (MIT); models the
classic traceroute(8) / mtr ICMP method (Van Jacobson's TTL-stepping
technique, public knowledge) and RFC 792 ICMP message formats via the
sibling `icmp` codec — see NOTICE. No traceroute, mtr or other third-party
source consulted or copied — behavior only.
