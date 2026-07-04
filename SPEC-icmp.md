# SPEC — `icmp` + `seqmap`

Extract the **ICMP echo (ping) engine** and its **sequence map** from zig-fping. Two modules from
one task. Wave P1 ("already a library, just carve out"). **Seeds:
`~/workspace/zig-fping/src/{seqmap,icmp,socket,pinger}.zig`** (fping-derived → the **fping license
attribution already in NOTICE for `netaddr` applies; extend/confirm the NOTICE entry**). Register:
`.{ .name = "seqmap" }` (no deps) and `.{ .name = "icmp", .deps = &.{ "seqmap", "netaddr" } }`.
`seqmap` = `extract · any · util · reentrant`; `icmp` = `extract · linux · client · single_owner`.

## Why

zig-fping already IS a working pure-Zig ICMP library; `netaddr` was the first carve-out. This lifts
the rest: the reusable **echo/reply codec + raw-socket + pacing engine** (`icmp`) and the O(1)
**16-bit-id → in-flight correlation map** (`seqmap`). No small pure-Zig ICMP lib exists otherwise.

## `seqmap` (small, do first)

Fixed **65536-slot** round-robin map: 16-bit ICMP sequence id → in-flight probe state
`{ target, probe_index, sent_ns }`. O(1) `add` (returns/consumes a seq), `fetch(seq)`, `release(seq)`;
**no per-op allocation** (fixed array). Extract from `seqmap.zig` verbatim; generalize the stored
payload to a small generic struct if clean, else keep the seed's fields. Model after fping
`seqmap.c`. Dep-free, portable (pure logic — usable by any request/reply protocol, not just ICMP).

- Tests: add→fetch round-trip, release frees the slot, wraparound at 65536, full-table behavior,
  O(1)/no-alloc (no allocator param). `zig build test-seqmap` green.

## `icmp` (the engine)

1. **Echo codec (pure, golden-tested):** build/parse ICMPv4 echo request/reply (type 8/0) and ICMPv6
   echo (type 128/129); Internet checksum (v4) and the v6 pseudo-header handling as the seed does;
   id/seq/payload. Bounds-checked parse, never panic on a short/garbage packet.
2. **Socket:** the raw/datagram ICMP socket from the seed — prefer **unprivileged `SOCK_DGRAM` +
   `IPPROTO_ICMP`/`ICMPV6`** (works without root when `ping_group_range` allows), fall back to
   `SOCK_RAW` (needs CAP_NET_RAW). Errno-encoded `std.os.linux`, no libc (repo discipline). `sendmmsg`
   batching if the seed has it — port faithfully.
3. **Pinger:** send echoes to a set of targets and correlate replies via `seqmap`, measuring RTT;
   the seed's global send-pacing / in-flight cap. Use `netaddr` for address parse/format. Port the
   reusable engine core from `pinger.zig` faithfully — **do NOT redesign** the pacing (the known
   subnet-pacing O(k log k) nit is a FUTURE improvement, out of scope; extract as-is).

- Tests: **offline** — echo build→parse round-trip + checksum golden (v4 + v6), parse rejects
  short/garbage (no panic), seqmap integration. **Integration (gate via `error.SkipZigTest` if the
  socket can't open — no CAP_NET_RAW and restrictive `ping_group_range`):** ping **127.0.0.1** (v4)
  and **::1** (v6) → a matching echo reply with a plausible RTT; assert id/seq correlation.
- `zig build test-icmp` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check` clean.

## Public API sketch (final = the seed's shape)

```zig
// seqmap
pub const SeqMap = struct {
    pub fn init() SeqMap;
    pub fn add(self, entry: Entry) ?u16;      // null if full
    pub fn fetch(self, seq: u16) ?Entry;
    pub fn release(self, seq: u16) void;
};
// icmp
pub const Pinger = struct {
    pub fn init(gpa, Options) !Pinger;   // family, pacing, timeout, count
    pub fn deinit(*Pinger) void;
    pub fn add(self, target: netaddr.Ip) !void;
    pub fn run(self) !void;               // or poll()/tick() — match the seed
    // results: per-target RTT / loss
};
pub const echo = struct { pub fn build(...) []u8; pub fn parse(bytes) !Reply; };
```

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 raw syscalls (errno-encoded `std.os.linux`, `sendmmsg`/`recvmmsg`
  if used — same discipline as the repo's http/dns/netlink raw paths). No libc.
- This is an **EXTRACTION** of a proven fping port: keep the codec + pacing semantics and the seed's
  tests; adapt module layout + any 0.16 stdlib drift. `icmp` depends on the already-built `seqmap` and
  `netaddr`.
- **Provenance/licensing:** `icmp`/`seqmap` are fping-derived (via zig-fping) → the **fping/Stanford
  attribution is REQUIRED** (it's already in `NOTICE` for netaddr — add `icmp`/`seqmap` to that same
  fping attribution note). README `Provenance:` line = "extracted from zig-fping `src/{...}.zig`
  (fping-derived — see NOTICE)". SPDX MIT header.
- Keep `seqmap` dep-free and portable; `icmp` is Linux-only by design (raw sockets).
