# `traceroute` verification instruments

One oracle, run by hand; its transcripts are frozen in
`src/kernel_oracle_vectors.zig` and replayed by `src/kernel_oracle_test.zig`
in the module's own lane, with no namespaces (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-traceroute`: runs `kernel_oracle.py judge`, and is itself what runs inside the client namespace (`--trace DEST icmp\|udp\|icmp-dgram MAX_HOPS PROBES TIMEOUT_MS`: `traceWith` over the live `LinuxTransport`, every call recorded, the clock virtual). Writes the vectors, or with `--check` compares their `//= ` verdict lines. |
| `go_oracle/` | RFC 5837 Interface Information: `golang.org/x/net/icmp` v0.61.0 marshals and parses messages from this module's case tables; `GOFLAGS=-mod=mod GOPROXY=off go run . -out ../../src/if_info_vectors.zig`, then `zig fmt`. Replayed offline by `root.zig`. |
| `bench.zig` + `go_bench/` | `zig build bench-traceroute`: the wire path against Go `golang.org/x/net/icmp` v0.61.0 (echo encode v4/v6, Time Exceeded decode with and without an RFC 4884 MPLS extension, hostile-intake rejects; plus an informational `traceWith` 30-hop run). Needs go 1.26 and x/net v0.61.0 + x/sys v0.49.0 in the module cache. |
| `kernel_oracle.py` | Builds a fresh client → r1 → r2 → r3 → server chain per scenario (`ip netns` in `unshare -rmn`, forwarding routers, an nft rule per scenario), runs our trace and traceroute(8), and judges both against the topology. |

```bash
zig build interop-traceroute              # re-take, write src/kernel_oracle_vectors.zig (~90 s)
zig build interop-traceroute -- --check   # re-take, compare the verdicts
```

Needs python3, `unshare`, `ip`, `nft`, `ping`, `ethtool` and traceroute(8); no root, no
network, nothing on the host changes. `--check` compares verdicts, not bytes:
a router's packets carry IPv4 IDs (its own, and the quoted probe's) that no
re-take reproduces, so the raw transcript is refreshed instead.

**What the replay holds** (2026-11-02, Linux 7.0, traceroute 2.1.6): 44
traces — ICMP over a raw socket, UDP, ICMP over an unprivileged ping socket
(`icmp-dgram`) and UDP over its own error queue (`udp-dgram`), v4 and v6, four
scenarios each, and the flow-stable variants of three of them in two scenarios.
One more scenario, not replayed: `ecmp`, a router balancing by the 5-tuple
(`--check` holds its verdict) — every hop the
topology's router at that TTL, traceroute(8) the same.
