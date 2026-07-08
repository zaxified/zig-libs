# SPEC — `icmp`

**Purpose** — An ICMP echo (**ping**) engine for monitoring workloads that check thousands of hosts
per cycle. std has no ICMP support and no small pure-Zig ICMP library exists, so this is the
liveness half of the network tail (paired with `traceroute` for path and `probe` for service
reachability). Three layers: a pure ICMPv4/v6 echo/timestamp wire codec, non-blocking Linux ICMP
sockets, and `Pinger` — fping's `main_loop` as a library (global pacing, in-flight cap, per-subnet
spacing, retries, reply correlation).

**Model after / Seed** — fping (schweikert/fping) `main_loop`, extracted from the authors'
`zig-fping` `src/{icmp,socket,pinger}.zig` (a Zig port of fping) — plus that port's scaling
additions: binary-heap scheduling, in-flight cap, per-subnet spacing, first-probe jitter,
sendmmsg/recvmmsg. The required fping/Stanford attribution is in `NOTICE` (shared by
netaddr/dns/icmp/seqmap). Wire formats per RFC 792 (ICMP), RFC 4443 (ICMPv6), RFC 1071 (checksum).

**Design & invariants**
- **Layered, codec is pure:** `echo` — build/parse + internet checksum, bounds-checked, never panics
  on garbage; `Socket` — non-blocking sockets; `Pinger` — the paced engine.
- **Unprivileged first:** `SOCK_DGRAM` + `IPPROTO_ICMP`/`ICMPV6` when `net.ipv4.ping_group_range`
  covers the process group, `SOCK_RAW` fallback (needs CAP_NET_RAW/root). Batched sends via
  `sendmmsg` (only when `interval_ns == 0`), batched receives via `recvmmsg`; kernel `SO_TIMESTAMPNS`
  receive timestamps for accurate RTT under load. IPv6 echo checksum left zero (kernel owns the
  pseudo-header for both DGRAM and RAW).
- **Concurrency:** single_owner — one thread/loop owns a `Pinger`; `stop()` is async-signal-safe.
  Reply correlation is delegated to the sibling `seqmap`, so the in-flight cap must stay < 65536.
- **Platform:** Linux-only by design — errno-encoded `std.os.linux` raw syscalls, no libc
  (a conscious ceiling per BRIEF); no portable fallback. Addresses via the sibling `netaddr`.
- **Modes** mirror fping: `.alive` (stop a target at first reply, retry timeouts with backoff),
  `.count` (exactly N), `.loop` (until `stop()`).

**Threat model / out of scope** — Raw/DGRAM ICMP sockets need CAP_NET_RAW or a permissive
`ping_group_range`; the module does not acquire privilege, only uses what it is given. It does **not
authenticate replies** — a reply is matched to a live probe by echo ident + sequence via `seqmap`, so
a spoofed reply with a guessed id resolves as genuine (correlation, not authentication). ICMP errors
(unreachable, time exceeded) are counted but the probe still resolves via timeout. Out of scope:
non-Linux platforms, capture/BPF, and any anti-spoofing token.

**Verification** — Offline: RFC 1071 checksum goldens (vector + wire-byte goldens v4/v6, comptime +
property variants), build→parse round trips, error-quote parsing, fuzzed parsers (never panic on
garbage), scheduler/pacing units, seqmap correlation. Integration: pings `127.0.0.1` / `::1`
end-to-end and asserts a correlated reply with plausible RTT, skipped via `error.SkipZigTest` when no
ICMP socket can be opened (no CAP_NET_RAW and a restrictive `ping_group_range`).

**Status** — `extract · linux · client · single_owner` · deps: `seqmap`, `netaddr`.
