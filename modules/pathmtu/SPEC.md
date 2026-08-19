# pathmtu — specification

Design + threat notes for auditors. Usage: see ./README.md.

## What this module is, and what it is not

Path MTU discovery for one destination: `query` reads whatever the kernel's
own PMTU destination cache already holds (unprivileged, instant, but blind
to a specific failure mode — see below); `probe` is an authoritative DF-bit
binary search over a real ICMP socket that finds the true path MTU itself
and, in doing so, can tell a well-behaved path from an ICMP black hole.

**What a reader might reasonably expect here and not find:** continuous or
background PMTU monitoring (this is a one-shot discovery, called when a
caller wants an answer, not a daemon that watches a route's MTU over time);
automatic egress-interface resolution (`Options.iface` is caller-supplied —
see "What is deliberately not done"); non-Linux support (`IP_MTU_DISCOVER`/
`IPV6_MTU_DISCOVER` are Linux-specific kernel facilities, and `probe`'s live
path additionally depends on the sibling `icmp` module's raw-syscall ICMP
socket). traceroute's own SPEC.md names "MTU/PMTU discovery" in its
out-of-scope list — this module is that gap, filled as the fourth member of
the `icmp`/`probe`/`traceroute` family.

## Design & invariants

Two independent paths sharing one `Result`/`Options` shape:

- **`query`** — raw `std.os.linux` socket calls only (no `icmp` dependency
  needed; no ICMP is sent or parsed here). `SOL.IP`/`SOL.IPV6`
  `MTU_DISCOVER = PMTUDISC_DO`, connect, one oversized nudge send (`EMSGSIZE`
  expected and ignored), `getsockopt(IP_MTU`/`IPV6_MTU)`. This is
  deliberately the prior in-house proven approach, unchanged in shape — the value
  this module adds is `probe`, not a rewrite of what already worked.
- **`probe`** — a pure binary-search engine (`searchWith`) behind an
  injectable `Prober` seam (`ctx: *anyopaque` + a function pointer — the
  same shape traceroute's `Transport` uses for its own offline testability),
  plus a live `Prober` (`LiveProber`) that owns a real `icmp.Socket`
  (`Mode.auto`: unprivileged DGRAM if `net.ipv4.ping_group_range` permits
  it, RAW otherwise — CAP_NET_RAW) and turns each candidate wire size into a
  send + receive-with-timeout-and-retries cycle. `searchWith` itself touches
  no socket, no clock, and allocates nothing — it is what the offline
  `FakeProber` tests exercise directly, independent of any network.

**The search invariant.** `lo` is the largest wire size believed to get
through (starts at the protocol floor, verified by our own probe before the
search proper begins — see "Limits and refusals"); `hi` is the smallest
size believed not to. Each probe outcome narrows the interval
(`applyOutcome`): `.ok` raises `lo` to the confirmed-good size;
`.local_reject`/`.no_reply` lower `hi` to the probed size itself (both are
our own direct observations). `.frag_needed` is the one case that can move
*both* bounds at once: when it carries a valid RFC 1191/4443 next-hop-MTU
hint `h` strictly inside `(lo, size)`, the search trusts it the way a real
kernel PMTUD implementation does — `lo` jumps to `h` and `hi` to `h + 1`,
converging immediately without re-probing that exact size (this is the one
place `lo` moves on something other than our own confirmed `.ok`, and is a
deliberate trust decision, not an oversight — see "Threat model" for what
trusting an unauthenticated hint costs). Without a usable hint, `hi` simply
drops to the probed size, and bisection proceeds as usual. The loop
terminates because `mid = lo + (hi-lo)/2` is always strictly inside
`(lo, hi)` once `hi - lo >= 2`, so every iteration shrinks the interval —
**given `searchWith`'s own `ceiling > floor` precondition holds**, which it
now checks itself (`error.CeilingTooLow` otherwise — see "Limits and
refusals"). That check used to be a bare `std.debug.assert`, and an audit
(2026-08-18) found the gap that left: `assert` compiles out entirely in
ReleaseFast/ReleaseSmall, so a caller of this `pub` function — which this
doc comment itself invites, for substituting a transport — violating the
precondition in that lane didn't panic, it underflowed `hi - lo` on
unsigned `u16` arithmetic and looped from a huge wrapped starting value
until killed (confirmed: 15+ seconds, see CHANGELOG.md). Termination is
structural now for every call that returns a `Result` at all; a call that
would have violated the precondition gets a checked error instead of a
hang, in every build mode alike.

**The black-hole signal.** Two booleans accumulate across the whole search:
`saw_frag_needed` (set by any `.frag_needed` outcome, from *any* candidate
size) and `saw_timeout_boundary` (set by any `.no_reply` outcome that
narrowed `hi`). `Result.blackhole = saw_timeout_boundary and
!saw_frag_needed` — true only when every narrowing-by-failure in the entire
search happened via silence, never via a real ICMP message. A single
genuine Fragmentation-Needed/Packet-Too-Big anywhere in the search clears
it, even if a *different* candidate size also timed out — this is a
deliberate, documented limitation (see "What is deliberately not done"),
not an oversight: a single binary search cannot distinguish "one hop is
silent" from "the whole path is silent" once any hop has spoken up.
`.local_reject` (`EMSGSIZE` from the *local* kernel, against the outgoing
interface's own configured MTU) narrows `hi` like a failure but touches
neither flag — it is a real, definitive signal, but a purely local one that
says nothing about the remote path.

**RFC 1191/4443 MTU hint.** Read directly from the raw ICMP bytes rather
than through the sibling `icmp.echo` module's `Reply.icmp_error` (which
exposes `kind`/`code`/`orig_ident`/`orig_seq` but not this field — it is
consumer-specific to path MTU discovery, out of scope for a general ICMP
codec). v4: 2 bytes at ICMP header offset 6 (`mtuHintV4`) — the low half of
RFC 792's "unused" field, repurposed by RFC 1191; a pre-RFC-1191 router
leaves it zero, read as "no hint". v6: 4 bytes at offset 4 (`mtuHintV6`,
RFC 4443 §3.2) — always meaningful for a conformant Packet Too Big message.
A hint is trusted only when it lies strictly inside the current search
interval (`applyOutcome`); an out-of-range or inconsistent value falls back
to treating the probed size itself as the new bound, so a malformed or
hostile hint can only make the search slower, never wrong.

## Threat model / out of scope

`probe`'s live path needs a real ICMP socket (see above); responses are
correlated by ident+seq quoted in the ICMP error, the same authentication
posture as the sibling `traceroute` module — **not authenticated**, a
spoofed off-path reply with the right ident/seq would be accepted as a real
signal. Concretely for this module: a spoofed Fragmentation-Needed/Packet
Too Big carrying a forged MTU hint is trusted the same way a genuine one is
(see "The search invariant" above) — bounded above by whatever size the
attacker's spoof responds to (a hint outside `(lo, size)` is discarded), so
a forgery can steer the reported MTU down within that range, or clear
`blackhole` by supplying `saw_frag_needed`, but cannot claim a size larger
than what has already failed.

**That is the weaker of the two directions, and an audit (2026-08-18) found
this document only ever named that one.** The stronger direction: a
forged, matching *echo reply* (not a Frag-Needed/Packet-Too-Big) triggers
`applyOutcome`'s `.ok` arm, which sets `lo.* = size` **unconditionally** —
`classify` accepts it on ident+seq match alone, no payload check, no
binding to anything about the specific probe beyond those two fields. A
single forged echo reply matching ident+seq for the very first (ceiling
-size) probe converges the *entire* search immediately to
`mtu = ceiling, blackhole = false` — a **falsely large** reported MTU. This
is the more dangerous direction, not merely the missing half of a
symmetric weakness: `blackhole = false` and a big number is exactly the
"everything's fine" signal a caller trusts and stops investigating on — the
one shape this module exists to independently confirm before a caller
believes it, and the one direction the spoofed-hint case above structurally
*cannot* produce (a hint can only push the answer down, or clear
`blackhole`, never claim a size larger than something that already failed).
This is not a new hole — `probe`'s live path was already, and remains,
completely unauthenticated end to end, same as `traceroute` states for
itself — it is a direction of the *same* hole this document previously did
not name.

*What stands between an attacker and a successful forgery, and for whom.*
Two ICMP fields gate acceptance: `ident` (whatever the sibling `icmp`
module's `Socket.open` assigned — RAW sockets: the process's own PID
`& 0xffff`, a handful of guesses on a freshly started process, often
single digits in a container; DGRAM sockets: a kernel-assigned ephemeral
port, ~28000 possible values on this host's default range) and `seq`
(entirely this module's own choice). Neither is a secret from an **on-path**
attacker — one who can observe this session's real ICMP traffic (a
compromised router on the path, a monitoring tap) sees every real ident,
seq, and payload byte the moment a probe leaves the wire, and needs to
guess nothing. No value this module could randomize, pad, or nonce inside
its own probe packets changes that; this module's posture toward an
on-path attacker is, and stays, exactly `traceroute`'s own stated one —
**not a security boundary** — and no code change below alters that
sentence's truth.

Against a **blind off-path** attacker — one spoofing source addresses
without seeing this session's real traffic, who must therefore *guess*
ident+seq — the picture is different, and was worse than documented before
this audit: `seq` started at the fixed value 1 and incremented by exactly 1
per attempt, so a blind attacker needed only to guess `ident` once and then
spray roughly the first ~15–20 sequential `seq` values to land a forged
reply on every probe the search would ever issue, for either address family
or socket kind. `probe` now seeds `seq` from a per-call `getrandom(2)` draw
(`randomStartSeq`, Linux-only direct syscall, matching the posture `ssh`/
`bulletproofs` already use elsewhere in this repo for the same reason —
CONVENTIONS.md §2.2's named deliberate exceptions to threading `std.Io`
through for a random draw) rather than the fixed value 1. A blind attacker
now has to guess a full unknown 16-bit `seq` in addition to `ident`, raising
the cost of a successful blind forgery by roughly `2^16`. This is a real,
honestly-scoped improvement and nothing more: 16 bits is not a
cryptographic margin, `ident` for a RAW-socket session is still PID-shaped
and not randomized by this module (that value belongs to the sibling `icmp`
module, outside this module's own surface), and a sufficiently
high-volume, sufficiently patient blind spoofer is not ruled out — only
made materially more expensive. It does **nothing at all** for an attacker
who is not blind, per the paragraph above.

Two further candidates were considered and deliberately **not** implemented:
- **Randomizing `ident` from within `pathmtu`.** Not this module's value to
  change — it is assigned by the sibling `icmp` module's `Socket.open` (PID
  for RAW, kernel ephemeral port for DGRAM) and this module does not touch
  `icmp`'s internals. Would need `icmp` module changes, out of this
  module's scope.
- **A per-probe nonce woven into the echo payload, checked on receipt.**
  Technically reachable entirely within `classify` (which already sees the
  raw ICMP bytes past the echo header) without touching `icmp`. Not added:
  its only genuine benefit over the `seq` randomization above is a larger
  guess space against the *same* attacker class (blind off-path) — it adds
  no protection against an on-path attacker either, for the same reason
  `seq`/`ident` don't (the payload is just as visible on the wire as the
  header). Given the marginal benefit is "harder to blind-guess by more
  bits," not "stops a new attacker," it did not clear the bar for the added
  complexity (payload construction, `classify` signature, per-attempt nonce
  bookkeeping) — an honest "raises the bar further against the same limited
  attacker" is not the same claim as "closes the gap," and this document
  does not want to imply the latter for a module whose live path is, and
  states itself to be, unauthenticated.

Malformed/hostile ICMP bytes never panic — `classify` reads fixed offsets
only after `icmp.echo.parseV4`/`parseV6`'s own bounds-checked parse has
already validated the message shape, and additionally guards its own
8-byte minimum before reading the MTU-hint offsets; see the fuzz test. Out
of scope: non-Linux platforms, continuous/background monitoring, UDP/TCP-
based PMTU probing methods (this module is ICMP/DF-bit only, per RFC
1191/8201), automatic egress-interface resolution.

## Limits and refusals

- **Protocol floor** (`min_mtu_v4 = 68`, RFC 791; `min_mtu_v6 = 1280`, RFC
  8200 §5) — `searchWith` verifies this size gets through *before* starting
  the real search; if it doesn't, the destination is unreachable outright
  (`error.Unreachable`), not merely MTU-limited, and no black-hole
  conclusion is drawn from it.
- **Starting ceiling** (`default_ceiling_mtu = 1500`, `Options.ceiling_mtu`,
  or `Options.iface`'s `SIOCGIFMTU` reading, in that priority) —
  `error.CeilingTooLow` if the resolved ceiling is at or below the floor;
  refused rather than silently returning a fabricated `Result`. `searchWith`
  itself now enforces the equivalent `ceiling > floor` precondition (see
  "The search invariant" above) as a checked error, not only `probe()`.
- **`max_probe_mtu = 9000`** — the fixed stack buffer `LiveProber` builds
  echo requests in (covers common jumbo-frame ceilings; zero-filled once at
  construction, not `undefined` — see below), and the hard cap `probe()`
  enforces on any ceiling it will ever search up to. An `Options.iface`-
  derived ceiling above this is **clamped** down silently (an
  auto-*derived* value, not a stated caller expectation); an explicit
  `Options.ceiling_mtu` above this is **refused** (`error.CeilingTooHigh`),
  not clamped — a caller who names a ceiling this module can never probe is
  stating an expectation the module cannot meet, and answering with a
  `Result` bounded by a smaller, unrequested ceiling would silently answer
  a different question than the one asked, the same failure shape
  `CeilingTooLow` above already refuses rather than commits. No allocator
  is used anywhere in this module.

  An audit (2026-08-18) found that `Options.ceiling_mtu` previously flowed
  into `LiveProber` completely unchecked: `probe()` clamped only the
  `iface`-derived ceiling (`@min(m, max_probe_mtu)`), so a caller-supplied
  `ceiling_mtu` above 9000 reached `LiveProber.attempt`'s
  `payload_len = wire_size - ip_header_len` slice into the fixed
  `[max_probe_mtu]u8` buffer unclamped. In Debug/ReleaseSafe this panicked
  (`index out of bounds`); in **ReleaseFast, Zig's own slice-bounds check
  compiles out along with every other runtime safety check** — `attempt`
  read past the end of the buffer, handed the over-length slice to
  `sendTo`/`sendto(2)`, and the kernel put whatever was on the stack past
  that 9000 bytes onto the wire as ICMP echo payload: a stack-memory
  disclosure to the probed destination, returning a fabricated
  `Result{ .mtu = <the bogus ceiling>, .blackhole = false }` rather than an
  error (confirmed: `mtu=20000 blackhole=false` for `ceiling_mtu = 20000`,
  followed by a SIGSEGV on return from the corrupted stack frame). Fixed by
  refusing (`error.CeilingTooHigh`) before any of it is built, so the
  buffer invariant holds for every caller by construction, not only a
  polite one; `LiveProber.attempt` also carries a defense-in-depth
  `@panic`-based check on the same condition (deliberately not another
  `std.debug.assert` — the same reasoning as above: an `assert` here would
  repeat the exact failure mode that let this bug through ReleaseFast in
  the first place). Separately, `LiveProber.buf` is now zero-filled at
  construction rather than `undefined`: `echo.writeEchoRequest` only
  writes the 8-byte echo header, and payload bytes beyond it were
  previously whatever the stack last held — leaking uninitialized stack
  content as ICMP payload on every probe, not only the out-of-bounds one
  above (smaller blast radius, same root cause; found while fixing the
  headline defect).

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — `probe`'s wire classification (`classify`, the ICMP-message
  → outcome step, including the RFC 1191/4443 MTU-hint offsets) is a wire
  format other implementations — and real routers — must agree with; an
  outside truth exists and the oracle may not be `n/a`.
- **Oracle MIXED**: `classify` is EXTERNAL-anchored (see below); the pure
  search algorithm (`searchWith`) is SELF — an internal algorithm with no
  outside truth to check it against, tested instead for the properties that
  matter (exact convergence, the blackhole/well-behaved distinction) via a
  fake, in-process `Prober`.

### External anchor: a real forwarding router, a real lowered-MTU link

The premise the whole module rests on — that a black hole is a real,
reproducible network condition and not a hypothetical — was verified live,
not just reasoned about. Method (2026-08-18), inside one fully unprivileged
`unshare --user --net` sandbox on this host (`unshare -rn`-class isolation;
no sudo, no setcap, nothing on the host changed):

1. Three more `unshare --net` namespaces (client, router, server — each an
   anonymous netns tied to a disposable `sleep` process, joined by `veth`
   pairs; no named `ip netns`, so nothing persists past the shell exiting).
2. `veth-c`↔`veth-r1` (client↔router, MTU 1500 both sides) and
   `veth-r2`↔`veth-s` (router↔server, MTU **1300** both sides — the
   deliberately lowered link).
3. Real kernel IP forwarding on the router
   (`net.ipv4.conf.all.forwarding=1`, `net.ipv6.conf.all.forwarding=1`) —
   this is a genuine forwarding router, not a simulation, exactly like
   `traceroute`'s own real-capture methodology (`../../traceroute/src/root.zig`,
   "real-capture goldens").
4. From the client netns: `ping -M do -s 1400 <server>` (DF bit, 1400-byte
   payload → 1428-byte IP datagram, exceeding the router's 1300-byte
   outbound link) — and the IPv6 equivalent.

**Result:** the router's real kernel sent back genuine ICMP Destination
Unreachable/Fragmentation Needed (v4, next-hop MTU 1300) and ICMPv6 Packet
Too Big (v6, MTU 1300) — captured with `tcpdump -xx` on the client's
interface, frozen into this module's test suite as
`real_v4_frag_needed`/`real_v6_packet_too_big` (`src/root.zig`, "real-capture
goldens"). Both decode correctly under `classify`, and the MTU-hint fields
this module reads (`mtuHintV4`/`mtuHintV6`) read back exactly 1300 from
real kernel bytes, not from a value this module's own encoder produced —
the standard for an external anchor.

**Then, separately: the black hole itself, and `query`'s blind spot to
it.** An `nft` rule on the router (`nft add rule ip filter output icmp type
destination-unreachable drop`) dropped the router's own outgoing
Frag-Needed reply while it still refused to forward the oversized DF
packet — the exact real-world shape (a firewall eating ICMP errors) this
module's `blackhole` flag exists to catch. Two things were confirmed live,
against a **fresh** destination address (`10.0.1.3`, never previously
probed, so the kernel had no pre-existing PMTU exception to fall back on —
`10.0.1.2`, used for step 4 above, does have one and would have hidden the
effect):

- `ip route get 10.0.1.3` on the client showed a bare `cache` entry with
  **no `mtu` field** — the kernel genuinely learned nothing.
- A direct repeat of `query`'s own syscall sequence
  (`IP_MTU_DISCOVER=PMTUDISC_DO`, oversized send, `getsockopt(IP_MTU)`)
  against both destinations, from the same client netns: **`10.0.1.2` → 1300
  (correct, a real exception exists)**; **`10.0.1.3` → 1500 (the interface's
  own MTU — wrong, silently indistinguishable from "no problem")**.

This is not re-run inside `zig build test-pathmtu`: it needs a network
namespace, `nft`, and root, none of which the CI sandbox has, and
constructing a 3-node forwarding topology inside a unit test would be far
more fragile than the frozen bytes it would produce — the same call
`traceroute`, `icmp` and `netlink`'s own real-capture sections make. What
*is* checked automatically is everything downstream of "a black hole is
real and produces these exact bytes": `classify` against the frozen real
capture, and the full `searchWith` state machine (well-behaved vs.
black-holed, converging to the identical MTU with a different `blackhole`
flag) against a fake `Prober`, in `src/root.zig`'s test section.

### Self: the search algorithm

`searchWith`'s binary-search correctness (exact convergence to the true
boundary, the blackhole-flag derivation, `local_reject`'s neutrality, a
mixed-signal path) has no outside authority to check it against — it is
this module's own design, following the *public technique* RFC 1191 and
Linux `tracepath(8)` describe (bisect on DF-probe failure) rather than a
byte-exact wire format. Graded and tested as SELF: the `FakeProber` tests
in `src/root.zig` construct known ground truth (`real_mtu`) and assert
exact convergence, including a property test across six different
bottleneck values chosen to not share an alignment with the search's own
arithmetic (`feedback_mutate_the_constant`-shaped: the assertion is on the
*value* found, not on the mechanism that found it).

## What is deliberately not done

- **Automatic egress-interface resolution.** Determining which local
  interface routes to `dest` (so `Result.iface_mtu` could be filled in
  without the caller naming it) would need either a route-table lookup
  (netlink `RTM_GETROUTE`, a real dependency this module doesn't otherwise
  need) or a `connect()`+`getsockname()`+interface-address-matching trick
  layered on `SIOCGIFCONF`/`/proc/net/if_inet6`. Both are real, buildable
  mechanisms, but the value — a display nicety ("1492 of a local 1500"
  instead of a bare number) — didn't justify either dependency or the
  IPv4/IPv6-asymmetric parsing complexity. `Options.iface` +
  `pathmtu.ifaceMtu(name)` gets a caller the same information for the one
  extra line of naming their own interface. **Not now**, not never — if a
  consumer needs it, the mechanism above is the honest way to build it.
- **A single search cannot separate two distinct hops' behavior.** If one
  router genuinely sends ICMP feedback and a *different* hop on the same
  path silently drops, one binary search sees only the tighter of the two
  boundaries and (per the black-hole derivation above) reports
  `blackhole = false` because *some* real ICMP was seen — even though the
  actual bottleneck might be the silent hop. Distinguishing this would need
  per-hop TTL-limited probing (traceroute's own method) combined with
  per-hop PMTU probing, a materially different and heavier design. Not
  attempted here; documented as a known limitation
  (`searchWith: one explicit Frag-Needed anywhere clears blackhole...`
  test names it explicitly).
- **Continuous/background PMTU monitoring.** `probe` is one-shot by design,
  matching `sntp.query`/`stun.query`'s convention; a caller that wants
  periodic re-checks calls it periodically.

## Open

Nothing else known missing or unverified beyond what's stated above.
