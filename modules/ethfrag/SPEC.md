# ethfrag — spec

Design + threat notes for auditors. Usage: see `src/root.zig` doc comments (no README —
this module is a standalone codec with no separate consumer-facing surface beyond the two
public entry points, `fragment`/`Reassembler`, already documented at their declarations).
Attribution/provenance: see `/NOTICE` — none needed here (clean-room from RFC 791 §3.2 /
RFC 5722 §3, both public specs, not third-party source).

## Design & invariants

Two halves, both pure (no I/O, no clock reads): `fragment()` splits an inner frame into
`header_len`(8)-byte-headered wire fragments sized to `carrier_mtu - header_overhead -
header_len`; `Reassembler` is a bounded stateful table keyed by `frag_id` that accepts
fragments in any order and returns a frame only once its accepted, non-overlapping
fragments sum to exactly its established total length (see the completion-correctness
argument in `src/root.zig`'s `insert` doc comment: non-overlapping intervals within
`[0, total_len)` whose lengths sum to `total_len` necessarily tile it with zero gaps —
so "sum of accepted lengths == total_len" is sufficient to prove full coverage without a
separate gap scan). **That premise — every accepted interval lies within
`[0, total_len)` — used to be unenforced for fragments accepted before any `more=false`
fragment had established `total_len` in the first place**: an out-of-range fragment
arriving first (while the bound is still unknown) sailed through the bounds check that
only exists once `total_len` IS known, then its length still counted toward `covered`.
A specific offset/order combination could make `covered` reach `total_len` via bytes
that lived entirely OUTSIDE the real frame while a genuine gap remained INSIDE it,
returning `.complete` over uninitialized allocator memory for that gap — found and
fixed while building `kernel_oracle.zig`'s teeth check; see `insert`'s retroactive
bounds check (fires the moment `total_len` is newly established) and the regression
test "reassembler rejects a fragment retroactively found to exceed a LATER-established
total length" in `root.zig`. `offset`/`length` are `u16`, which is both the wire format and the
`max_frame_len` ceiling (65535 bytes) — a width tied directly to the header, not a
separate policy knob. Concurrency: `.reentrant` free functions; a `Reassembler` instance
is single-owner (no internal lock — one caller drives it, matching `ratelimit`/`jobqueue`
style bounded-state modules in this collection).

Every reassembly-table entry pre-allocates a fixed `config.max_frame_len`-byte buffer up
front rather than growing on demand — total worst-case reassembler memory is therefore a
deterministic `max_inflight * max_frame_len`, independent of what an attacker actually
sends, which is the property the hard-resource-bounds goal asks for. The clock is 100%
caller-supplied: every state-mutating call takes a plain `now_ns: u64`, and the module
never calls `clock_gettime` or anything else itself — a consumer wires in whatever clock
domain (monotonic, simulated, or a network-time source) fits its event loop.

## Threat model / out of scope

Modeled directly on the IP-fragmentation CVE playbook, each item mapped to a concrete
enforcement point in `Reassembler.insert`:

- **Overlap / evasion (RFC 5722 §3, teardrop's modern descendant):** any fragment whose
  `[offset, offset+length)` overlaps a byte range already accepted for that `frag_id`
  drops the **entire** in-flight datagram, not just the offending fragment. This
  includes an exact byte-for-byte duplicate, which is simply the overlap-with-itself
  case — there is deliberately no separate "identical bytes, so merge it" fast path,
  because that distinction is exactly what overlap-based IDS-evasion attacks rely on.
- **Teardrop overrun:** a fragment claiming to extend past an already-established total
  length (`more=false` seen once, or the running `max_frame_len` ceiling) is rejected as
  `OutOfBounds`, and a second, disagreeing `more=false` claim is rejected as
  `ProtocolViolation` — both drop the whole datagram.
- **Tiny-fragment flood:** `config.max_fragments_per_datagram` (default
  `max_fragments_per_frame` = 4096) caps how many pieces one datagram may be split
  across on receive; `fragment()` enforces the same cap on send. A flood of 1-byte
  fragments for one `frag_id` trips `TooManyFragments` well before it can grow the
  per-datagram interval list unboundedly.
- **Incomplete-reassembly memory exhaustion:** `config.max_inflight` caps the number of
  concurrently tracked `frag_id`s; once full, a new id is rejected (`TableFull`) unless
  an `expireOlderThan` sweep reclaims a timed-out slot. Total memory is the
  deterministic bound described above — an attacker cannot grow it past
  `max_inflight * max_frame_len` no matter how many fragments or datagrams it sends.
- **Gap-then-never-completes:** `config.timeout_ns`, checked against caller-supplied
  `now_ns`, drops a datagram idle too long — either lazily (touched again by a fragment
  for the same id) or via an explicit `expireOlderThan` sweep. A very late fragment for
  an already-expired id starts a **fresh** reassembly rather than resurrecting stale
  bytes; it never partially completes against pruned state.
- **Reserved-field smuggling:** `Header.decode` rejects any nonzero reserved flag bit or
  reserved byte outright (`InvalidHeader`) rather than masking and ignoring them — a
  strict decoder, not a lenient one.
- **Never a partial frame:** there is exactly one return path that yields `.complete`,
  gated on `covered == total_len` after the overlap/bounds checks above already ran; no
  other code path constructs or returns frame bytes.
- **Malformed/hostile bytes never panic:** every offset/length arithmetic path is
  bounds-checked before touching the reassembly buffer (`frag_end > max_frame_len`
  rejected before any `@memcpy`); truncated or over-long wire buffers are rejected
  (`Truncated`, `LengthMismatch`) before the header's claimed length is trusted for a
  copy. See the fuzz target for the standing regression check.

**Out of scope (by design, not oversight):** this is a standalone codec — no network I/O,
no `frag_id` allocation/uniqueness policy (that's the caller's job, exactly as IPv4's
identification field is the sender's job), no fragment retransmission/NACK, no
authentication of fragment origin (a spoofed fragment with a guessed `frag_id` can poison
or exhaust a slot exactly as a spoofed IP fragment can — bound by the same
`max_inflight`/`timeout_ns` limits as any other adversarial sender, not a distinct
weakness introduced by this module).

## Verification

Offline by default — this is a pure codec, no live-interop surface at runtime.
`zig build test-ethfrag`: round-trip smoke (no-frag, zero-length, multi-fragment,
reordered delivery), a 300-iteration seeded property test (`fragment` → shuffle →
`Reassembler` → exact byte-identical output, across random frame lengths/MTUs/header-overheads), a targeted
adversarial corpus (one test per threat-model bullet above: overlap, duplicate, teardrop
overrun, contradictory final-length claims, oversized frame, tiny-fragment flood,
resource-cap exhaustion, gap-then-timeout, malformed header, truncated bytes, length
mismatch, out-of-bounds), `std.testing.fuzz` over the reassembler's raw wire-byte
input (structurally-valid-but-hostile fragments plus fully arbitrary bytes), asserting
only "never panics" + "`inflightCount()` never exceeds `max_inflight`", and an
**external anchor** (`src/kernel_oracle.zig`) freezing 12 real IPv4/IPv6 fragment
captures (six scenarios × two address families — in-order, out-of-order,
missing-middle, exact-duplicate, conflicting-overlap, content-consistent-but-
differently-sliced-overlap) plus the real Linux kernel's own observed accept/drop
verdict for each, captured once inside an unprivileged
`unshare --user --map-root-user --net` namespace with hand-built raw sockets (no
`scapy`). Every capture's fragment shape is replayed through this module's own
production `Reassembler` (re-encoded into its own wire format) and the two verdicts
are compared offline thereafter — no kernel access needed to run the suite. Ten of
twelve match; the remaining two are ethfrag's one confirmed, deliberate divergence
from the kernel (see that file's doc comment): this module treats an exact-duplicate
fragment as just another overlap and drops the whole datagram, while this host's
kernel tolerates it as a harmless retransmission for both IPv4 and IPv6. Green in
Debug and `-Doptimize=ReleaseFast`.

## Backlog / deferred

None. No Fable-tier piece was needed — every requirement (overlap/duplicate/timeout
rejection, resource bounds, teardrop-class hardening) is protocol/state-machine logic
with a well-specified reference (RFC 791 §3.2, RFC 5722 §3), not novel cryptography or
adversarial-math reasoning.

## Status

`extract · any · codec · reentrant` · deps: none (std only) — canonical source is
`pub const meta` in `src/root.zig`.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/kernel_oracle.zig grades this module's Reassembler verdict against the real Linux kernel's own IPv4/IPv6 fragment reassembly, 6 scenarios x {v4,v6} = 12 captured comparisons; the emit/fragmentation side and the overlap policy beyond those scenarios stay self

**How it got there.** The anchoring work landed. DONE b8612e1: kernel reassembly oracle; UNINITIALISED-MEMORY bug fixed; 1 policy divergence
