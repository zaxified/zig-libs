# `netaddr` verification instruments

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-netaddr [-- --check]`: re-takes the three oracles below and writes (or compares) their vectors; the interop lane runs it with `--check`. Its header lists what each needs. |
| `go_netip_oracle/` | Go `net/netip` + go4.org/netipx as a black box → `src/netip_vectors.zig`. |
| `parse_oracle.py` | glibc `inet_pton`/`inet_ntop` and Python `ipaddress` as black boxes → `src/parse_vectors.zig`. |
| `rfc6724_oracle.py` | glibc `getaddrinfo` destination order and the Linux source choice → `src/rfc6724_vectors.zig`. |
| `bench.zig` + `go_bench/` | `zig build bench-netaddr`: comparative benchmark against Go `net/netip` + netipx, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). Seven workloads over 1,000 generated inputs each (parse IPv4/IPv6, format IPv6, `Prefix.contains`, sort, `IpSet` build and lookup); both sides double the batch until it takes 100 ms and keep the best of five; result counts must agree or the run fails. Needs the same netipx module cache as the oracle. Not run by any lane. 2026-10-07, x86-64: 0.24–0.88 (ours/Go, worst `parse_v4`). |
