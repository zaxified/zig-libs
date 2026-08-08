# l2forward

A pure-Zig **E-LAN edge forwarding table** for a multi-tenant, encrypted L2VPN
fabric. It is the forwarding *brain* a provider edge (PE) runs: given a customer
Ethernet frame's `{ I-SID, destination MAC, ingress }` it decides **where to
send it** — to one remote PE (a learned unicast), replicated to the I-SID's
member PEs (a BUM/unknown flood), or nowhere at all when the frame came out of
the core. It owns the per-tenant state (MAC learning + membership); the sibling [`l2encap`](../l2encap/README.md) codec
builds the actual on-wire frame. Pure, deterministic, time-injected, bounded: no
socket, no clock, no thread — the caller drives `now` and all I/O.

Status: **gap** — the S1b L2-over-WireGuard data plane needs the per-tenant
MAC-learning + replication brain that `l2encap` deliberately does *not* carry
(its SPEC's deferred list names "MAC learning" and "the actual next-hop
selection" as out of scope); this fills exactly that slot. Model + rationale
below; full design/threat notes in [SPEC.md](SPEC.md).

## Model-after

- **IEEE 802.1D MAC learning / ageing FDB** — the per-tenant forwarding database
  is an 802.1D bridge learning table: learn source MAC → port (here, remote PE)
  from received frames, age entries out after an inactivity time, flood on a
  miss.
- **IEEE 802.1ah PBB I-SID service scoping** — every FDB and member set is keyed
  by the 24-bit **I-SID**, so each tenant is an isolated learning domain (the
  same MAC in two I-SIDs is two unrelated entries).
- **EVPN (RFC 7432) / SPB (IEEE 802.1aq) ingress replication + full-mesh
  split-horizon** — a BUM frame received on a local **access** circuit is
  replicated to the I-SID's member PEs; a frame received from the **core** is
  never put back into the fabric at all (RFC 4762 §4.4, RFC 7432 §8.3.1),
  matching `l2encap`'s `droppedBySplitHorizon` predicate.

## Pairing with `l2encap`

The two modules split state from wire and agree by construction — same 24-bit
I-SID, same 16-bit PE id, same split-horizon rule:

```
                    ┌── membership + FDB (this module) ──┐
received frame ──▶  l2forward.forward(isid, dst, ingress) ──▶ Decision
                                                              │
       unicast(pe) / flood({pe…}) / local_only  ───────────▶ l2encap.encode(fields…)
                                                              (builds the frame per remote PE)
```

`l2forward` answers *who* gets the frame; `l2encap` builds *what* goes on the
wire (the tenant tag, TTL loop-backstop, BUM + ingress-PE fields). This module
imports neither `l2encap` nor any transport — separation of concerns; the caller
chains them.

## The forward decision

`forward(isid, dst_mac, ingress, now, out) → Decision`, where `ingress` is
`.access` (a local customer port) or `.core = pe` (out of the fabric, replicated
by remote PE `pe` — `l2encap.decode` supplies that id):

- **from the core** → `Decision.local_only`, always, whatever the destination:
  deliver to local access circuits and put nothing back into the fabric. The
  full mesh means every other member already got its own copy from the ingress
  PE (RFC 4762 §4.4, RFC 7432 §8.3.1).
- **from access, known unicast** — `dst_mac` is a fresh FDB hit in `isid` →
  `Decision.unicast(pe)`: send to that one remote PE.
- **from access, BUM** → `Decision.flood(set)`: the I-SID's member PEs, written
  into the caller-supplied `out` buffer, ascending by PE id (deterministic).
  Members are the *remote* PEs, so there is nothing to exclude. The set may be
  empty (no members, or an unknown I-SID).

**BUM classification** (Broadcast / Unknown-unicast / Multicast):

- **broadcast** — `dst_mac` is all-ones (`isBroadcast`).
- **multicast** — the I/G bit (LSB of the first octet) is set (`isMulticast`);
  broadcast is its all-ones special case.
- **unknown unicast** — an individual (I/G-clear) address that misses the FDB in
  `isid` (or whose entry has aged out).

`isBumAddress(dst)` decides broadcast/multicast from the address alone; the
unknown-unicast case is decided inside `forward` against the FDB.

## Split-horizon, tenant isolation, ageing

- **Split-horizon** — the replication set for a core-received frame is
  **empty**, never "members minus the source". Excluding only the source would
  relay the frame to the other N−2 members, each of which would relay again —
  `(N−1)(N−2)^(k−1)` copies at hop k, stopped only by `l2encap`'s TTL. The
  claimed ingress PE is an attacker-controlled header field, and the rule does
  not depend on its value.
- **Tenant isolation** — the I-SID is the top-level key; a MAC learned in one
  I-SID is invisible to every other. A flood or MAC-move in tenant A can never
  affect tenant B.
- **Ageing** — `tick(now)` reclaims dynamic entries older than
  `Options.aging_ticks`; an expired MAC reverts to unknown-unicast (floods
  again). `forward`/`lookup` already treat an over-age entry as a miss, so `tick`
  is memory reclamation only — forwarding is correct between ticks. A **static**
  entry (`learnStatic`) is never aged and is not overwritten by dynamic learning.

## MAC-move & capacity (the DoS bound)

- **MAC move — reported and counted** (EVPN RFC 7432 §15). Re-learning a MAC now
  seen from a different PE updates the entry in place; it is one entry, not two.
  But the frame that causes a move is unauthenticated, so a move is a possible
  **hijack**, not just mobility: `learn` therefore returns a `LearnOutcome`
  (`.moved` and friends) so the caller is always told, and counts moves. The move
  that reaches `Options.max_mac_moves` (default 5) inside
  `Options.mac_move_window` (default 180) is **refused** and the MAC is
  **quarantined** — no binding is trusted, so it floods to every member PE (which
  still reaches the real station) until the window lapses. `moveCount` /
  `isQuarantined` expose the state; `forget` / `learnStatic` clear it.
- **The data plane cannot create tenants** — `learn` refuses an I-SID the control
  plane never configured (`error.UnknownIsid`) and allocates nothing for it. Only
  `addIsid` / `addMember` / `learnStatic` provision a tenant slot, so received
  traffic can never spend the `max_isids` budget.
- **MAC-flood bound** — the learning table is capped **per tenant** by
  `Options.max_macs_per_isid`. When a tenant's FDB is full, `learn` first
  reclaims that tenant's expired entries; if still full a *new* MAC is rejected
  (`error.FdbFull`) — learning fails closed, existing entries untouched, and the
  unlearned MAC just forwards as unknown-unicast (floods), exactly as a real
  bridge degrades to flooding when its CAM fills. `max_isids` and
  `max_pes_per_isid` similarly bound the I-SID count and per-I-SID membership.
  Total worst-case memory is `max_isids × max_macs_per_isid` FDB entries plus
  `max_isids × max_pes_per_isid` membership entries — never unbounded, but at
  the shipped defaults that ceiling is at least ~500 MiB before hashmap
  bookkeeping overhead (see `SPEC.md` §"Deliberately generous defaults") —
  size `max_isids`/`max_macs_per_isid` down for a memory-constrained edge PE.

## Time-injection contract

The table never reads a clock. Every entry point that ages state takes a
caller-supplied monotonic `now: Time` (abstract ticks in the caller's own unit;
`aging_ticks` is in the same unit). Given the same `(ops, now)` stream the table
yields the same decisions on every run, and every flood set is in ascending PE-id
order — both pinned by permanent tests.

## API

- `Table.init(alloc, options) Table` / `deinit()` — `Options` carries the caps
  (`max_isids`, `max_pes_per_isid`, `max_macs_per_isid`), `aging_ticks` and the
  MAC-mobility limits (`max_mac_moves`, `mac_move_window`).
- `addIsid(isid) !void` / `removeIsid(isid) bool` — control-plane tenant
  provisioning (a tenant may legitimately have no members).
- `addMember(isid, pe) !void` / `removeMember(isid, pe)` / `isMember(...) bool` /
  `memberCount(isid) usize` — control-plane-populated membership.
- `learn(isid, mac, pe, now) !LearnOutcome` — dynamic learning; the outcome
  (`.learned` / `.refreshed` / `.moved` / `.duplicate_detected` /
  `.denied_duplicate` / `.static_pinned`) is the caller's hijack notification and
  is not optional to think about. `learnStatic(isid, mac, pe) !void` — pinned,
  never-aged, never quarantined; `forget(isid, mac) bool` — delete.
- `moveCount(isid, mac) u8` / `isQuarantined(isid, mac) bool` — MAC-mobility
  state.
- `lookup(isid, mac, now) ?PeId` — the PE a known unicast would take, or null.
- `forward(isid, dst, ingress, now, out) !Decision` — the forward decision;
  `replicationSet(isid, ingress, out) ![]const PeId` — the replication set
  directly, for a pre-classified BUM frame.
- `tick(now)` — reclaim aged entries. `fdbCount(isid)` / `isidCount()` — sizes.
- `isBroadcast(mac)` / `isMulticast(mac)` / `isBumAddress(dst)` — pure BUM
  classification helpers.

## Test

```
zig build test-l2forward
```

Unit tests cover BUM classification (broadcast/multicast/unicast); known-unicast
learn→forward and its unknown-unicast fallback; full-mesh split horizon
(access BUM floods all of `{2,3,4}`, core BUM floods nobody); a **hostile-peer**
test that a lying/absent `ingress_pe` buys no relay; a 4-PE fabric composition
test that one access broadcast yields exactly 3 copies and dies at hop 1
(pre-fix: `(N−1)(N−2)^(k−1)`, bounded only by TTL); tenant
isolation (a MAC in I-SID A is unknown in B); MAC move (one entry, reported);
a **MAC-hijack** test (a move is reported and counted; a flapping MAC is
quarantined, the refused move is not installed, it floods instead of being
unicast to the thief, sending more neither extends the quarantine nor lets
ageing reclaim it, and the window's expiry re-opens learning); a
**tenant-provisioning** test (100 unconfigured I-SIDs from the data plane are
each refused with `UnknownIsid` and `isidCount()` stays 0);
ageing (fresh at the boundary, gone past it, `tick` reclaims, re-learn
refreshes) and static entries; the per-tenant MAC-flood bound (`FdbFull` after a
reclaim attempt, existing entries unaffected) plus I-SID/member caps;
determinism (identical `(ops, now)` → identical decisions, insertion-order-
independent sorted flood set); a permanent positive-control test proving that
the old "members − src_pe" set is a non-empty *relay* where the rule demands
nothing; and a leak check
(`testing.allocator`) that `deinit` frees every nested map. Green in Debug and
`-Doptimize=ReleaseFast`.

Provenance: clean-room from public specifications (IEEE 802.1D, IEEE 802.1ah,
IEEE 802.1aq SPB, EVPN RFC 7432) — no third-party source or dissector consulted
or copied. No `/NOTICE` entry needed (spec citations live in SPEC.md). License:
MIT.
