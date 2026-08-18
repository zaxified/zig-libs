# pathmtu

Path MTU discovery for IPv4/IPv6 on Linux: `query` reads the kernel's own
PMTU cache (fast, unprivileged); `probe` runs an authoritative DF-bit binary
search that finds the same answer even when the kernel's cache cannot — the
ICMP black-hole case, where a middlebox drops an oversized packet without
sending back the Fragmentation-Needed/Packet-Too-Big message the kernel
needs to learn from.

- Std has no PMTU discovery support at all.
- **Model after:** RFC 1191 (IPv4 PMTUD) / RFC 8201 (IPv6 PMTUD) / RFC 4443
  §3.2 (Packet Too Big) and `ip(7)`/`ipv6(7)`'s `IP_MTU_DISCOVER`/`IP_MTU`
  documentation for `query`; Linux `tracepath(8)`'s DF-probe binary-search
  method (behavior only) for `probe`.
- **Platform:** linux (`IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER` are Linux-only;
  `probe` also opens a real ICMP socket via the sibling `icmp` module).
  **Role:** client. **Concurrency:** reentrant (no shared state — each call
  opens its own socket).
- **Deps:** `icmp` (echo codec + DF-capable socket for `probe`), `netaddr`
  (`Ip` addressing).

Provenance: clean-room from the RFCs above. AXP's own prior ~25-line
kernel-cache implementation (same organization, not a third-party project)
was read as the starting point for `query` and is superseded by this
module — no root `NOTICE` entry applies (no third-party source studied or
ported).

## Why two functions

`query` is what AXP had: set `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER` to
`PMTUDISC_DO` on a connected UDP socket, send one oversized nudge datagram,
read `IP_MTU`/`IPV6_MTU` back. Instant, unprivileged, and correct whenever
the kernel's PMTU cache has actually been populated by a real ICMP message.

It is also **structurally unable** to tell "no problem at this size" apart
from "I never got an answer" — both read back as the outgoing interface's
own MTU. A middlebox that drops an oversized DF packet without sending the
ICMP back leaves the cache with nothing to learn, and `query` silently
reports the wrong number. `probe` exists for exactly this: it sends its own
DF-bit probes and binary-searches the boundary directly, so it can tell a
size that failed because a router replied with a real ICMP
Fragmentation-Needed/Packet-Too-Big (`Result.blackhole = false`) from a size
that failed because nothing answered at all after retries (`blackhole =
true`).

Measured on a real router forwarding onto a 1300-byte-MTU link (see
SPEC.md's "Anchoring" for the full method): with the router's own
Frag-Needed reply intact, `query` correctly reports 1300. With that same
ICMP dropped by the router's firewall, `query` reports 1500 (the interface's
own MTU) — silently wrong — while `probe` still finds 1300 and marks it
`blackhole = true`.

## API

```zig
const pathmtu = @import("pathmtu");
const netaddr = @import("netaddr");

const dest = netaddr.parseIp("203.0.113.1").?;

// Kernel cache -- unprivileged, instant, may be stale/wrong (see above).
const cached = try pathmtu.query(dest, .{});

// Authoritative DF-bit binary search -- needs CAP_NET_RAW, or an
// unprivileged ICMP DGRAM socket if net.ipv4.ping_group_range permits it.
const found = try pathmtu.probe(dest, .{ .timeout_ms = 1000, .retries = 2 });
// found.mtu, found.source (.probed), found.blackhole, found.iface_mtu
```

`Result{ mtu, source, blackhole, iface_mtu }`:

- `mtu` — the discovered/cached path MTU.
- `source` — `.cached` (from `query`) or `.probed` (from `probe`).
- `blackhole` — only ever set by `probe` (see above).
- `iface_mtu` — set when `Options.iface` names an interface; read via
  `SIOCGIFMTU` (also exposed directly as `pathmtu.ifaceMtu("eth0")`). This
  module does no automatic egress-interface resolution — see SPEC.md.

`Options{ timeout_ms, retries, ceiling_mtu, iface }` is shared by both
functions (matching `sntp.QueryOptions`/`stun.QueryOptions`'s
`timeout_ms`-based shape rather than inventing a third): `query` only reads
`iface`; the rest are `probe`-only.

`probe`'s pure binary-search engine is exposed as `searchWith(prober, floor,
ceiling, iface_mtu)` over an injectable `Prober` seam — this is what the
module's own tests exercise offline, and what a consumer could use to
substitute a different transport if ever needed.

## Tests

`zig build test-pathmtu` — the binary-search algorithm itself
(`searchWith`) against a fake, in-process `Prober`: exact convergence with
and without an ICMP MTU hint, the well-behaved-path-vs-black-hole
distinction converging to the *same* MTU with a *different* `blackhole`
flag, an unreachable floor, and a mixed-signal path. Wire classification
(`classify`, the ICMP-message-to-outcome step) is anchored against bytes
captured from a real Linux router forwarding a DF-oversized ping onto a
genuinely lowered-MTU link (a `veth` pair in an unprivileged network
namespace) — see SPEC.md "Anchoring" for the full method, including how the
kernel-cache blind spot itself was verified live. `probe`/`query` against
loopback are live-gated (`error.SkipZigTest` without the needed privilege).

## Deferred (not in v1)

- Automatic egress-interface resolution (no route lookup) — `Options.iface`
  is caller-supplied.
- IPv6 Fragment Header handling beyond DF-equivalent PMTUD (IPv6 has no DF
  bit; `IPV6_MTU_DISCOVER=PMTUDISC_DO` is the kernel's own equivalent, used
  here).
- Continuous/background PMTU monitoring — `probe` is a one-shot discovery.
