# l2forward — spec

Design + threat notes for auditors. Usage, API and the forward-decision
contract: see [README.md](README.md) and the `src/root.zig` doc comments.
Attribution/provenance: see `/NOTICE` — none needed here (clean-room from public
specs: IEEE 802.1D MAC learning/ageing, IEEE 802.1ah PBB I-SID service scoping,
IEEE 802.1aq SPB, EVPN RFC 7432 ingress replication + split-horizon; a public
spec is not a copyrightable work, and no third-party source or dissector was
ported or studied).

## Data model

`Table` holds one `AutoHashMapUnmanaged(Isid, IsidEntry)`. Each `IsidEntry` is a
tenant's isolated forwarding state:

- **members** — `AutoHashMapUnmanaged(PeId, void)`, a set of remote PEs the
  caller populates from the control plane (SPB I-SID TLVs / EVPN imports). This
  module never learns membership from data-plane frames.
- **the tenant slot itself** is control-plane state on exactly the same footing.
  Only `addIsid` (explicit provisioning, for a legitimately member-less
  single-PE I-SID), `addMember` and `learnStatic` create an `IsidEntry`;
  `removeIsid` drops one. The data-plane entry point `learn` **cannot**: an
  I-SID the caller never configured is refused with `error.UnknownIsid` and
  allocates nothing. Before 2026-08-07 `learn` called `getOrCreateIsid`
  unconditionally, which contradicted the sentence above it and let an attacker
  with no control-plane access walk the `max_isids` budget from received frames
  alone (audit finding F3).
- **fdb** — `AutoHashMapUnmanaged(Mac, FdbEntry)`, the 802.1D-style learning
  table. `FdbEntry = { pe: PeId, learned_at: Time, move_window_start: Time,
  moves: u8, static: bool, duplicate: bool }`. Ageing is
  *derived* from `learned_at` versus the caller-supplied `now` (a comparison,
  never an owned countdown), exactly the pattern the sibling `isis-lsdb` /
  `ramcache` use for time-injected freshness.

Plain field widths deliberately match `l2encap` so the two agree without a
conversion layer: `Isid = u24`, `PeId = u16`, `Mac = [6]u8`, `Time = u64`.
Concurrency is `.single_owner`: one thread/loop owns the table, no internal lock.

## Forward decision & BUM classification

`forward(isid, dst, ingress, now, out)`, where `ingress` is `.access` (a local
customer circuit) or `.core = pe` (out of the fabric, ingress-replicated by
remote PE `pe`):

0. If `ingress` is `.core` → `Decision.local_only`, before any table lookup.
   Nothing received from the core re-enters the fabric (see Split-horizon).
1. If `dst` is a **broadcast or multicast** address (`isBumAddress` — the I/G
   bit, LSB of the first octet; broadcast all-ones is its special case) → BUM.
2. Else look `dst` up in `isid`'s FDB. A **fresh hit** → `Decision.unicast(pe)`.
   A **miss or an over-age entry** → unknown-unicast → BUM.
3. For any BUM case → `Decision.flood(set)`, `set` = `replicationSet`.

Classification order matters: an address is BUM by *shape* (broadcast/multicast)
independent of any table; only the individual-address case consults the FDB.
This is why `isBumAddress` is a pure exported predicate and the unknown-unicast
decision lives inside `forward`.

## Split-horizon

`replicationSet(isid, ingress, out)`:

- `.core` → the **empty** set, unconditionally. RFC 4762 §4.4 (VPLS: a PE must
  not forward a frame received on one mesh PW onto another mesh PW) and RFC 7432
  §8.3.1 (EVPN ingress replication) both make the PE-to-PE mesh full, so every
  member already received its own copy directly from the ingress PE. The claimed
  ingress PE id is an attacker-controlled header field (`l2encap`'s
  `ingress_pe`); the rule deliberately does not consult its value.
- `.access` → every member of `isid`, written into the caller's buffer and
  **sorted ascending by PE id**. Members are by definition the *remote* PEs, so
  the local PE is never in its own member set and there is nothing to subtract.

The sort is load-bearing: `AutoHashMap` iteration order tracks internal
insert/remove history and is not stable, so an unsorted set would make the flood
decision non-deterministic across equivalent tables. Sorting a set bounded by
`max_pes_per_isid` is cheap and gives a total, reproducible order. `out` too
small for the set is `error.BufferTooSmall`; sizing `out` to `max_pes_per_isid`
makes that unreachable.

**Superseded rule (kept so the change is legible).** This module previously
returned *members − `src_pe`* for every BUM frame, and `forward` had no way to
say a frame came from the core. That is not a weaker split horizon, it is a
relay: with N members, hop k carries `(N−1)(N−2)^(k−1)` copies of one broadcast
— at N=4, `3·2^63` frames, stopped only when `l2encap`'s TTL (default 64) runs
out. `l2encap.droppedBySplitHorizon` cannot catch the relayed copies either,
because `ingress_pe` is stamped once at ingress and preserved across
`decrementTtl`, so a third PE never recognises a copy as relayed. Pinned by the
4-PE composition test in `src/root.zig`.

### Honest scope of the loop claim (do not overclaim)

The failure mode this rule *does* close is the **steady-state core relay** in a
fully converged fabric — the exponential duplication described above. It needs no
reconvergence, no misconfiguration and no malformed frame: it is what a faithful
`l2forward` + `l2encap` integration did on every broadcast. That is now
prevented by construction, because a core-received frame yields `local_only`.
(An earlier revision of this paragraph named only the *transient reconvergence*
loop as the residual risk. That was the wrong failure mode: the dominant one was
in the steady state, and it was ours.)

What is still **not** closed here: a transient forwarding loop among PEs during
control-plane reconvergence, when the member sets of different PEs disagree.
That needs a loop-free BUM distribution tree and a reverse-path-forwarding
check, which are **control-plane** computations (the `loopfree-reconv` /
SPB-tree work), not something a per-frame forwarding table can assert. The
always-correct data-plane backstop for that residue is `l2encap`'s **TTL**: a
loop the control plane briefly allows dies after at most `initial_ttl` PE hops.
This module supplies the *necessary inputs* (the member set + the ingress
classification); the finite-loop guarantee is TTL's, and true loop-freedom is
the control plane's. `l2forward` therefore performs **ingress replication to the
full member set**, not tree-pruned replication; a loop-free tree is out of scope
by design (deferred list). `l2encap`'s SPEC carried the same "honest scope"
paragraph and was corrected alongside this one.

## MAC-move policy (EVPN RFC 7432 §15)

Re-learning a MAC already present and **dynamic** behind a *different* PE is a
**move**. It is one entry, not a second. A move is not an anti-flap/stability
concern here, it is a **security** one: the frame that causes it is
unauthenticated data-plane input, so a spoofed source MAC redirects a station's
entire unicast flow to the attacker's PE. Until 2026-08-07 `learn` was plain
last-writer-wins returning `void` — no counter, no limit, no notification — so
one hostile frame stole a binding permanently and silently (audit finding F5).
The policy now:

- **`learn` returns a `LearnOutcome`**, never `void`: `.learned`, `.refreshed`,
  `.moved`, `.duplicate_detected`, `.denied_duplicate`, `.static_pinned`. A move
  is therefore always reported to the caller, which owns the policy response
  (alarm, ACL, pin with `learnStatic`). `moveCount` / `isQuarantined` expose the
  same state for inspection.
- **Moves are counted** per entry over a sliding window. The move that reaches
  `Options.max_mac_moves` (default 5) within `Options.mac_move_window` (default
  180 — RFC 7432 §15's stated N/M defaults) is **refused**, and the MAC is
  **quarantined**.
- **A quarantine means "nobody's binding is trusted"**, not "freeze the current
  one": `lookup`/`forward` report a miss, so the MAC floods to every member PE —
  which still reaches the real station — until the window lapses. Freezing
  instead would hand the attacker a permanent lock on whatever it had just
  stolen. The quarantine's window start is pinned at detection, so continuing to
  send cannot extend it, and a live quarantine also survives ageing/`tick` (else
  reclamation would erase the flag and return the MAC to the attacker). `forget`
  and `learnStatic` clear it immediately; after the window a fresh `learn`
  re-establishes the MAC from scratch, so a legitimate station is never
  permanently black-holed.
- A MAC pinned **static** is not moved and never quarantined (`.static_pinned`,
  silent, no error); `learnStatic` itself overwrites whatever was there
  (including a quarantined entry), and `forget` deletes either kind.

Residual: within `max_mac_moves - 1` moves per window an attacker still wins the
binding it stole, exactly as a real bridge does — that race is not decidable
without per-frame authentication (see the boundary note below). What the module
guarantees is that it is *bounded* and *reported*, never silent or permanent.

## Ageing model

A dynamic entry is expired when `now - learned_at > aging_ticks` (strictly
greater — age exactly `aging_ticks` is still fresh; a boundary test pins this).
`now < learned_at` (a non-monotonic clock) is treated as age 0 — never
spuriously expired. `forward`/`lookup` treat an expired entry as a miss *without
removing it* (lazy: forwarding stays correct between ticks); `tick(now)` is the
reclaimer that physically frees expired dynamic entries. Static entries ignore
ageing entirely. Because forwarding is already correct pre-reclamation, `tick`
may make partial or no progress under allocator pressure without affecting
correctness — it collects victims into a scratch list (a safe-removal buffer, as
the map iterator is invalidated by in-place removal) and, on scratch-alloc
failure, reclaims what it gathered and leaves the rest for the next tick.

## Capacity / DoS bound

The central threat of any learning FDB is a **source-MAC flood**: an attacker
spraying novel source MACs to exhaust memory. Bounds, all hard:

- **`max_macs_per_isid`** — the per-tenant FDB cap. On a new MAC while full,
  `learn` first prunes that tenant's expired entries (`pruneIsid`); if still full
  it returns `error.FdbFull`. Learning **fails closed** — existing entries are
  never evicted to admit an attacker's MAC — and the unlearned MAC forwards as
  unknown-unicast (floods), the same graceful degradation a hardware bridge shows
  when its CAM fills. **Reject, not LRU-evict**, is the deliberate choice: an
  eviction policy would let an attacker push out *legitimate* learned entries,
  turning a memory-exhaustion attack into a forwarding-disruption attack; rejecting
  caps memory without ever sacrificing a proven entry, and ageing reclaims the
  attacker's junk. The cost is that a full tenant temporarily learns no new MACs
  (they flood) until ageing frees room — an availability degradation, not a
  memory or cross-tenant compromise.
- **Per-tenant, not global** — the cap is per I-SID, so a flood in one tenant can
  never evict or starve another tenant's entries (tenant isolation extends to the
  DoS bound).
- **`max_isids`** bounds the number of distinct tenants that may hold state, and
  **`max_pes_per_isid`** bounds membership per tenant (and thus the maximum flood
  fan-out / replication-buffer size). A new I-SID beyond the cap →
  `error.TooManyIsids`; a new member beyond the cap → `error.TooManyMembers`.
- **Only the control plane can spend the `max_isids` budget.** `learn` refuses an
  unconfigured I-SID (`error.UnknownIsid`) instead of creating one, so the
  worst-case footprint below is a function of what the *operator* provisioned,
  never of received traffic. This matters because that footprint is large by
  construction — at the defaults `max_isids × max_macs_per_isid` is 4096 × 8192
  = 33,554,432 FDB entries, at LEAST ~500 MiB of raw `(Mac, FdbEntry)` bytes
  before `AutoHashMapUnmanaged`'s own bookkeeping overhead (control bytes,
  load-factor headroom) adds more on top — **not a bound an edge PE with a
  modest memory budget should treat as free**, only as "will not grow past
  this." Lower the defaults (or `max_isids` specifically, the dominant
  factor) for a memory-constrained deployment; the `SELF` test pinning this
  estimate lives in `root.zig` so a future field added to `FdbEntry` cannot
  silently make this paragraph stale — and reaching it must still require
  control-plane access.
- **`max_mac_moves` / `mac_move_window`** bound MAC *churn* rather than memory:
  a flapping MAC costs no extra entry, and duplicate detection stops an endless
  hijack loop (see the MAC-move policy).

Total worst-case footprint is therefore `max_isids × max_macs_per_isid` FDB
entries + `max_isids × max_pes_per_isid` membership entries — a fixed ceiling the
operator sets, never a function of received traffic.

**Not a confidentiality/authenticity boundary.** Like `l2encap`, this table
trusts the frames the fabric hands it; an attacker who can inject authenticated
in-tunnel frames can poison learning (a spoofed source MAC learned behind the
wrong PE) within the same fabric trust as any other in-tunnel byte. Per-frame
authentication is the caller's / control plane's concern (deferred list). What
this table does owe such an attacker is that the damage is **bounded and
visible** rather than unlimited and silent — hence: no tenant creation from the
data plane, per-tenant FDB caps, counted moves reported through `LearnOutcome`,
and duplicate-MAC quarantine. MAC-pinning *policy* on top of those signals
(which MACs to `learnStatic`, when to alarm) stays the caller's.

## Concurrency ceiling (wave-2 audit F7)

`meta.concurrency = .single_owner`: one thread/loop owns a `Table` and it
holds no internal lock (`root.zig:119`) — a plain `AutoHashMapUnmanaged`, no
atomics, no RCU. Correct and cheap in that shape, but it is a real ceiling
against the named C reference, not a nicety: the Linux kernel bridge FDB
(`net/bridge/br_fdb.c`) is RCU-protected with per-bucket locking, so lookups
run lock-free in parallel across every core while learning proceeds
concurrently on the same table. A `Table` cannot do that — a PE that wants to
forward at line rate across N cores against ONE `Table` needs an external
lock serialising the read path the kernel deliberately keeps parallel, which
gives up exactly the throughput scaling `br_fdb_find_rcu` provides.

**This module confirmed sits on a real L2VPN data-plane path** (F1, the
split-horizon fix, is what makes that concrete — this is not a hypothetical
consumer), so the ceiling is worth stating rather than leaving implicit:

- **What is NOT provided:** cross-thread scaling of `forward`/`learn` over
  one shared `Table`. Two threads calling into the same `Table` concurrently
  is undefined — the same single-owner contract every other `zig-libs`
  in-memory table in this family (`kv`, `kvtree`'s pager, `shardstore`'s own
  per-shard rule) already carries.
- **The accepted production shape today: one forwarding thread (one owning
  loop) per PE.** A PE's own `Table` is never shared across PE processes/
  threads by construction (it is PE-local FDB state), so this is not a
  scaling *bug* inside a single PE's own forwarding path — a single PE
  forwarding on one core is exactly the case this module is built for. The
  ceiling only bites if a *single* PE's data plane is itself sharded across
  multiple threads/cores against one `Table` — a shape this module does not
  support today.
- **If that shape is ever needed:** either (a) shard the table itself (N
  independent `Table`s keyed by a stable partition of I-SID or MAC, the same
  design `shardstore` already uses for `kvtree`), or (b) adopt an RCU/seqlock
  read path so lookups run lock-free while `learn`/`tick` mutate — both are
  real engineering, not a one-line fix, and neither is scheduled without a
  concrete multi-core-per-PE consumer to size it against (the standing
  perf-gate rule this repo already applies: no speculative concurrency
  investment without a measured, named consumer).

## Deliberately deferred (out of scope by design, not oversight)

- **Designated-forwarder (DF) election** — which PE forwards BUM into a
  multi-homed site; that is the separate `df-elect` module, which the caller
  consults before/around `forward`.
- **Loop-free BUM distribution trees / reverse-path-forwarding check** — this
  module does simple ingress replication to the full member set; a pruned
  loop-free tree is a control-plane computation (`loopfree-reconv` / SPB tree).
- **MAC-mobility *arbitration* across PEs** — the EVPN MAC-mobility extended
  community's sequence number, i.e. deciding which PE's advertisement wins in the
  *control plane*. Local duplicate-MAC detection (RFC 7432 §15's N-moves-in-M
  rule) is **not** deferred any more — it is implemented, see the MAC-move policy
  above. What remains out of scope is the inter-PE signalling that carries the
  verdict, plus flap dampening of the control-plane churn itself.
- **ARP/ND suppression & proxy-ARP** — answering ARP/ND from the FDB to cut BUM
  flooding is a higher-layer optimization, not modelled.
- **The frame itself** — encap/decap, TTL, fragmentation, encryption are
  `l2encap` / `ethfrag` / `wireguard`; this module returns a decision, not bytes,
  and imports none of them.
- **Control-plane distribution** — I-SID↔tenant binding, PE-id assignment, and
  membership import are the caller's; this table only stores the membership the
  caller hands it.

## Verification

Offline only — pure logic, no live-interop surface. `zig build test-l2forward`
(Debug + `-Doptimize=ReleaseFast`): BUM classification; known-unicast
learn→forward + unknown-unicast fallback; full-mesh split horizon (access BUM →
all of `{2,3,4}` ascending; core BUM → nobody; `BufferTooSmall`); a hostile-peer
test that no claimed `ingress_pe` — member, non-member or edge value — buys a
relay; a 4-PE fabric composition test that one access broadcast produces exactly
3 copies and stops at hop 1; tenant
isolation; MAC move (accepted, one entry); a MAC-hijack regression test — a move
is reported as `.moved` and counted, a flapping MAC is quarantined at
`max_mac_moves` (the refused move is *not* installed, the MAC floods to every
member instead, sending more neither extends the quarantine nor lets ageing
reclaim it, and the window's expiry re-opens learning); a tenant-provisioning
regression test — 100 unconfigured I-SIDs presented from the data plane are each
refused with `UnknownIsid` while `isidCount()` stays 0, and `addIsid` /
`addMember` / `learnStatic` / `removeIsid` open and close the door; ageing (boundary fresh/expired,
lazy miss + `tick` reclaim, re-learn refresh) and static-entry immunity; the
per-tenant MAC-flood bound (`FdbFull` after reclaim, existing entries + moves
still served) and I-SID/member caps; determinism (identical `(ops, now)` →
identical decisions, insertion-order-independent sorted flood set); a permanent
positive-control test proving that the superseded "members − src_pe" set is a
non-empty relay where the rule demands nothing (so a regression there goes red);
and a `testing.allocator` leak
check that `deinit` frees every nested membership + FDB map. `zig fmt --check`
clean; `zig build check-catalog` green.

### External-anchor investigation: a real Linux bridge FDB (2026-08-01, partly)

An audit task asked whether a real Linux bridge's FDB, observed in a namespace,
could anchor this module's MAC-learning/ageing/flooding semantics against the
kernel instead of against our reading of 802.1D. **This module never touches a
real interface or a raw frame** — `Table` operates on abstract `{Isid, PeId,
Mac, Time}` values the caller already parsed, so there is no wire format or
socket for a kernel bridge to share with it; the literal request ("capture what
the kernel's FDB does... and freeze those observations") cannot become a golden
byte test the way `l2encap`'s frames might have. What the live kernel *can*
validate is whether this module's documented semantic model — learn on receipt,
flood unknown, age out — actually matches a conformant 802.1D device, which is a
design-fidelity check, not a wire anchor.

That check was run: a 3-port bridge (`br0` + 3 veth pairs, one port used to
inject/observe each side) in an unprivileged `unshare --user --net` namespace
(no `tcpdump`/`-Z`; a small `AF_PACKET` Python script sent/observed raw frames).
Findings, with the exact commands/output:

- **The real kernel default `ageing_time` is 300 s** — `ip -d link show br0`
  (freshly created, nothing configured) reported `ageing_time 30000`
  (centiseconds). This is a genuine, freezable numeric fact and is now a golden
  test (`external anchor: our default aging_ticks matches...`, `src/root.zig`):
  `Options{}.aging_ticks == 300` is pinned against this real, live-captured
  kernel default, not merely against the 802.1D document.
- **Learn-on-receipt.** A crafted frame (`src=02:00:00:00:00:01`, broadcast
  dst) sent into port `veth1a` immediately produced, in `bridge fdb show br0`:
  `02:00:00:00:00:01 dev veth1a master br0` — learned before any forwarding
  decision, matching `learn`'s contract.
- **Flood on unknown/broadcast destination.** The same broadcast frame was
  observed (via raw sockets) arriving at *both* other ports (`veth2b` and
  `veth3b`) — matching `forward`'s BUM → flood-to-all-members path for an
  access-ingress frame.
- **Learned unicast is not flooded.** After also learning
  `02:00:00:00:00:02` behind the second port, a frame from the first port
  addressed to that MAC arrived *only* at the port it was learned behind
  (`veth2b`), not the third (`veth3b`) — matching known-unicast's single-PE
  `Decision.unicast`, distinct from flood.
- **Age-out.** With `ageing_time` lowered to `200` (2 s, for a practical test
  window — the *default* 300 s was confirmed separately above, not used for
  this timed part), the learned entry present in `bridge fdb show` right after
  learning was gone from `bridge fdb show` after waiting past the window —
  matching `tick`'s reclaim-after-expiry contract.

All four match this module's documented contract exactly; **no disagreement
was found**. None of the three behavioral findings (learn/flood/age-out) is
wired into the automated suite: `learn`/`flood` have no real-frame counterpart
in this module to assert against (there is nothing here that consumes a MAC
learned from an actual received Ethernet frame — the caller already extracts
`src_mac` before calling `learn`), and the age-out timing is real-wall-clock and
therefore exactly the kind of flaky, non-reproducible assertion this audit was
told to avoid pinning byte-for-byte. Only the one genuinely freezable number
(the 300 s default) was promoted to an automated, offline, kernel-anchored test.
No `/NOTICE` entry: black-box kernel behavior only, no source or design
consulted (root `NOTICE` §0).

## Status

`gap · any · util · single_owner` · deps: none (std only) — canonical source is
`pub const meta` in `src/root.zig`.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** narrow and only over defaults: src/root.zig:1304 pins aging_ticks to a live kernel bridge's observed ageing_time (30000 centiseconds) and :1436 pins the MAC-move defaults to RFC 7432 §15.1's stated N=5/M=180. Every FDB/learn/flood/split-horizon DECISION is still graded by this module's own tests; the live bridge's qualitative agreement was not wired in (timing-dependent, SPEC.md)

**How it got there.** The anchoring work landed. DONE a58d626: aging default pinned to live kernel bridge 300s; rest is timing-dependent
