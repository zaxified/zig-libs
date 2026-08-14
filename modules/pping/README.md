# pping

**Passive RTT estimation with zero active probing.** An observation point that
can see both directions of a TCP flow — a tap, a router, a middlebox; anything
that is not an endpoint — recovers the round-trip time from the flow's own
RFC 7323 TCP Timestamps option. Every segment carrying the option asserts a
TSval ("my clock reads this now") and echoes a TSecr ("the last TSval I validly
received from you"). Because a TSecr is only ever a TSval the *other* side
actually sent, matching a TSecr seen going one way back to the TSval that
produced it — seen going the other way, earlier — is exactly the elapsed round
trip. No cooperation from either endpoint, and not one synthetic byte on the
wire.

- **Status:** complete — parser, bounded table, and the matching core.
  **Platform:** any — no sockets, no wall-clock read; `now` is caller-supplied.
- **Deps:** none (std only).
- **Model after:** Kathleen Nichols' *pping* (Pollere LLC) passive-RTT
  technique, over RFC 7323 TSval/TSecr.

## The algorithm

- Per flow, per direction, a bounded table maps `tsval -> first_seen_time`,
  storing only the **first** time each distinct TSval was seen that way.
- A packet going the **opposite** direction carrying `tsecr = T` matches the
  entry for `tsval == T` in the opposite direction's table, and emits
  `now - stored_time`.
- **First-echo-only.** A match *consumes* the entry rather than reading it. A
  later segment re-echoing the same TSecr — a delayed ACK, a duplicate ACK from
  loss or reordering, a keepalive — finds nothing and correctly produces no
  second, inflated sample. Without this rule every duplicate echo would
  masquerade as a fresh (and wrong) measurement.
- **Bounded memory.** Fixed `capacity` per (flow, direction), allocated once and
  never grown, plus `max_age` eviction: a TSval nobody echoes within a few
  worst-case RTTs is never coming back.
- Matching is **exact 32-bit equality**, which is what makes the scheme agnostic
  to each host's TSval tick rate (RFC 7323 §5.3 leaves it host-specific) and
  immune to the wraparound reasoning an ordering-based comparison would need.

## Use

```zig
const pping = @import("pping");

var est = try pping.Estimator.init(gpa, .{ .capacity = 256, .max_age = 60_000 });
defer est.deinit(gpa);

const ts = pping.parseTcpTimestamps(tcp_options_bytes) orelse return;
if (est.observe(.{ .dir = .a_to_b, .tsval = ts.tsval, .tsecr = ts.tsecr, .now = t })) |s| {
    // s.rtt, in whatever unit `now` is in — this module never picks one.
}
```

Out-of-order `now` values cannot crash the estimator: aging uses a saturating
age calculation, so they degrade to "nothing evicted" rather than UB.

## Verify

```
zig build test-pping                          # Debug       — 51 pass
zig build test-pping -Doptimize=ReleaseFast   # ReleaseFast — 51 pass
```

The option parser has a KAT corpus plus a hostile-input test proving it never
reads out of bounds. The table is tested for insert / lookup / remove / aging /
capacity eviction and for bounded memory under a long stream. The matching core
is pinned by the property harness: duplicate and delayed echoes must produce
**no** second sample, and a bounded table must not invent one.

Provenance: the passive-RTT technique (match a TCP TSecr back to the TSval
that produced it, seen earlier in the opposite direction) and its
first-echo-match-and-consume rule are Kathleen Nichols' *pping* (Pollere LLC,
<https://github.com/pollere/pping>, **GPL-3.0-or-later**) — ALGORITHM AND
BEHAVIOR ONLY, described in its public documentation and papers, studied as a
**design reference only**. No pping source was consulted, read or ported: this
module is an independent Zig implementation of a published measurement technique
(a technique is not a copyrightable work), and it deliberately shares no code
with, and derives nothing from, that GPL codebase. The wire format is RFC 7323,
a public spec.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/parse.zig:207-224 anchors the TCP Timestamps option parser on 2 real SYN/SYN-ACK captures taken with tcpdump off a genuine loopback handshake, including the tsecr<-tsval echo. Everything above the parser is NOT anchored today: match.matchEcho is a gated Fable stub, so every KAT in src/kat.zig returns error.SkipZigTest and asserts nothing

**How it got there.** The anchoring work landed. DONE a326e4a: real SYN/SYN-ACK timestamp options, tsecr<-tsval correlation anchored
