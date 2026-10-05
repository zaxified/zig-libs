# `pathmtu` verification instruments

One oracle, run by hand; its answers are frozen in
`src/kernel_oracle_vectors.zig` and replayed by `src/kernel_oracle_test.zig`
in the module's own lane, with no namespaces (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-pathmtu`: runs `kernel_oracle.py judge`, and is itself what runs inside the client namespace (`--probe DEST IFACE TIMEOUT_MS RETRIES`: `query`, `probe` with every attempt recorded through `Options.on_attempt`, `query` again, as JSON). Writes (or with `--check` compares) the vectors. |
| `kernel_oracle.py` | Builds a fresh client → router → server topology per scenario (`ip netns` in `unshare -rmn`, veth pairs, a forwarding router, optional nft rule dropping the router's own ICMP errors), warms the path with small pings, runs the probe and iputils `tracepath`, and judges both against the configured link MTUs. |

```bash
zig build interop-pathmtu              # re-take, write src/kernel_oracle_vectors.zig (~90 s)
zig build interop-pathmtu -- --check   # re-take, compare with the committed file
```

Needs python3, `unshare`, `ip`, `nft`, `ping` and `tracepath`; no root, no
network, nothing on the host changes (a tmpfs over `/run` holds `/run/netns`
inside the private mount namespace).

**What the replay holds** (2026-10-05, Linux 7.0, iputils 20250605): 22
scenarios, v4 and v6, `probe` at the configured bottleneck in every one, a
black hole flagged exactly where the router drops its ICMP errors; `tracepath`
agreed on every well-behaved path and read the interface MTU through every
black hole, as `query` does.
