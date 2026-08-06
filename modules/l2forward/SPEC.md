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
- **fdb** — `AutoHashMapUnmanaged(Mac, FdbEntry)`, the 802.1D-style learning
  table. `FdbEntry = { pe: PeId, learned_at: Time, static: bool }`. Ageing is
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
check, which are **control-plane** computations (the S1b `loopfree-reconv` /
SPB-tree work), not something a per-frame forwarding table can assert. The
always-correct data-plane backstop for that residue is `l2encap`'s **TTL**: a
loop the control plane briefly allows dies after at most `initial_ttl` PE hops.
This module supplies the *necessary inputs* (the member set + the ingress
classification); the finite-loop guarantee is TTL's, and true loop-freedom is
the control plane's. `l2forward` therefore performs **ingress replication to the
full member set**, not tree-pruned replication; a loop-free tree is out of scope
by design (deferred list). `l2encap`'s SPEC carries the same "honest scope"
paragraph and still names only the transient case — it needs the same correction
in its own module.

## MAC-move policy

Re-learning a MAC already present and **dynamic** overwrites its `pe` and
refreshes `learned_at` — last-writer-wins / accept-move. It is one entry, not a
second; no flap dampening or move-rate limiting is applied here (that is a
deferred anti-flap concern). A MAC pinned **static** is not moved by dynamic
learning (the static entry wins, silently); `learnStatic` itself overwrites
whatever was there, and `forget` deletes either kind.

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

Total worst-case footprint is therefore `max_isids × max_macs_per_isid` FDB
entries + `max_isids × max_pes_per_isid` membership entries — a fixed ceiling the
operator sets, never a function of received traffic.

**Not a confidentiality/authenticity boundary.** Like `l2encap`, this table
trusts the frames the fabric hands it; an attacker who can inject authenticated
in-tunnel frames can poison learning (a spoofed source MAC learned behind the
wrong PE) within the same fabric trust as any other in-tunnel byte. Per-frame
authentication and MAC-pinning policy beyond the `static` flag are the caller's /
control plane's concern (deferred list).

## Deliberately deferred (out of scope by design, not oversight)

- **Designated-forwarder (DF) election** — which PE forwards BUM into a
  multi-homed site; that is the separate S1b `df-elect` module, which the caller
  consults before/around `forward`.
- **Loop-free BUM distribution trees / reverse-path-forwarding check** — this
  module does simple ingress replication to the full member set; a pruned
  loop-free tree is a control-plane computation (`loopfree-reconv` / SPB tree).
- **MAC mobility / anti-flap dampening** — move-rate limiting, flap suppression,
  sequence-number arbitration (EVPN MAC mobility extended community). `learn` is
  plain last-writer-wins.
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
isolation; MAC move (last-writer-wins, one entry); ageing (boundary fresh/expired,
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
