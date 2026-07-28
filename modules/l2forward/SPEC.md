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

`forward(isid, dst, src_pe, now, out)`:

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

`replicationSet(isid, src_pe, out)` returns every member of `isid` **except**
`src_pe`, written into the caller's buffer and **sorted ascending by PE id**. The
sort is load-bearing: `AutoHashMap` iteration order tracks internal
insert/remove history and is not stable, so an unsorted set would make the flood
decision non-deterministic across equivalent tables. Sorting a set bounded by
`max_pes_per_isid` is cheap and gives a total, reproducible order.

A `src_pe` that is not a member excludes nothing (all members are returned) — the
documented rule for a frame whose ingress PE the local table does not (yet) list
as a member. `out` too small for the filtered set is `error.BufferTooSmall`;
sizing `out` to `max_pes_per_isid` makes that unreachable.

### Honest scope of the loop claim (do not overclaim)

Split-horizon-as-source-PE-exclusion prevents exactly the **reflection** case: a
BUM frame delivered back toward the PE that ingress-replicated it. It does **not**
by itself prevent a transient forwarding loop among *other* PEs during
control-plane reconvergence — that needs a loop-free BUM distribution tree and a
reverse-path-forwarding check, which are **control-plane** computations (the S1b
`loopfree-reconv` / SPB-tree work), not something a per-frame forwarding table
can assert. The always-correct data-plane backstop is `l2encap`'s **TTL**: even a
loop the control plane briefly allows dies after at most `initial_ttl` PE hops.
This module supplies the *necessary inputs* (the member set + the split-horizon
filter); the finite-loop guarantee is TTL's, and true loop-freedom is the control
plane's. This division is intentional and matches `l2encap`'s SPEC exactly — see
its "Honest scope of the loop claim" section. `l2forward` therefore performs
**ingress replication to the full member set**, not tree-pruned replication; a
loop-free tree is out of scope by design (deferred list).

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
learn→forward + unknown-unicast fallback; split-horizon (`{2,3,4}` src 3 →
`{2,4}` ascending; non-member source excludes nothing; `BufferTooSmall`); tenant
isolation; MAC move (last-writer-wins, one entry); ageing (boundary fresh/expired,
lazy miss + `tick` reclaim, re-learn refresh) and static-entry immunity; the
per-tenant MAC-flood bound (`FdbFull` after reclaim, existing entries + moves
still served) and I-SID/member caps; determinism (identical `(ops, now)` →
identical decisions, insertion-order-independent sorted flood set); a permanent
positive-control test proving a flood set that *keeps* the source PE contradicts
split-horizon (so a regression there goes red); and a `testing.allocator` leak
check that `deinit` frees every nested membership + FDB map. `zig fmt --check`
clean; `zig build check-catalog` green.

## Status

`gap · any · util · single_owner` · deps: none (std only) — canonical source is
`pub const meta` in `src/root.zig`.
