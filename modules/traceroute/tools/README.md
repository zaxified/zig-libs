# `traceroute` verification instruments

One oracle, run by hand; its transcripts are frozen in
`src/kernel_oracle_vectors.zig` and replayed by `src/kernel_oracle_test.zig`
in the module's own lane, with no namespaces (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-traceroute`: runs `kernel_oracle.py judge`, and is itself what runs inside the client namespace (`--trace DEST icmp\|udp MAX_HOPS PROBES TIMEOUT_MS`: `traceWith` over the live `LinuxTransport`, every call recorded, the clock virtual). Writes the vectors, or with `--check` compares their `//= ` verdict lines. |
| `kernel_oracle.py` | Builds a fresh client → r1 → r2 → r3 → server chain per scenario (`ip netns` in `unshare -rmn`, forwarding routers, an nft rule per scenario), runs our trace and traceroute(8), and judges both against the topology. |

```bash
zig build interop-traceroute              # re-take, write src/kernel_oracle_vectors.zig (~90 s)
zig build interop-traceroute -- --check   # re-take, compare the verdicts
```

Needs python3, `unshare`, `ip`, `nft`, `ping` and traceroute(8); no root, no
network, nothing on the host changes. `--check` compares verdicts, not bytes:
a router's packets carry IPv4 IDs (its own, and the quoted probe's) that no
re-take reproduces, so the raw transcript is refreshed instead.

**What the replay holds** (2026-10-05, Linux 7.0, traceroute 2.1.6): 16
traces, every hop the topology's router at that TTL, traceroute(8) the same.
