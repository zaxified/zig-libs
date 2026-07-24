# l2forward

A pure-Zig **E-LAN edge forwarding table** for a multi-tenant, encrypted L2VPN
fabric. It is the forwarding *brain* a provider edge (PE) runs: given a customer
Ethernet frame's `{ I-SID, destination MAC, source PE }` it decides **where to
send it** — to one remote PE (a learned unicast), or replicated to the I-SID's
member PEs minus the source (a BUM/unknown flood). It owns the per-tenant state
(MAC learning + membership); the sibling [`l2encap`](../l2encap/README.md) codec
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
- **EVPN (RFC 7432) / SPB (IEEE 802.1aq) ingress replication + split-horizon** —
  a BUM frame is replicated to the I-SID's member PEs *minus the source PE* (the
  split-horizon rule that stops a PE echoing a BUM frame back toward its
  originator), matching `l2encap`'s `droppedBySplitHorizon` predicate.

## Pairing with `l2encap`

The two modules split state from wire and agree by construction — same 24-bit
I-SID, same 16-bit PE id, same split-horizon rule:

```
                    ┌── membership + FDB (this module) ──┐
received frame ──▶  l2forward.forward(isid, dst, src_pe) ──▶ Decision
                                                              │
              unicast(pe) / flood({pe…})  ──────────────────▶ l2encap.encode(fields…)
                                                              (builds the frame per remote PE)
```

`l2forward` answers *who* gets the frame; `l2encap` builds *what* goes on the
wire (the tenant tag, TTL loop-backstop, BUM + ingress-PE fields). This module
imports neither `l2encap` nor any transport — separation of concerns; the caller
chains them.

## The forward decision

`forward(isid, dst_mac, src_pe, now, out) → Decision`:

- **known unicast** — `dst_mac` is a fresh FDB hit in `isid` →
  `Decision.unicast(pe)`: send to that one remote PE.
- **BUM** → `Decision.flood(set)`: the I-SID's member PEs **minus `src_pe`**
  (split-horizon), written into the caller-supplied `out` buffer, ascending by
  PE id (deterministic). The set may be empty (no other members, or an unknown
  I-SID).

**BUM classification** (Broadcast / Unknown-unicast / Multicast):

- **broadcast** — `dst_mac` is all-ones (`isBroadcast`).
- **multicast** — the I/G bit (LSB of the first octet) is set (`isMulticast`);
  broadcast is its all-ones special case.
- **unknown unicast** — an individual (I/G-clear) address that misses the FDB in
  `isid` (or whose entry has aged out).

`isBumAddress(dst)` decides broadcast/multicast from the address alone; the
unknown-unicast case is decided inside `forward` against the FDB.

## Split-horizon, tenant isolation, ageing

- **Split-horizon** — a flood set never contains `src_pe`: a BUM frame is never
  replicated back toward the PE it arrived from (the E-LAN duplicate/loop guard,
  matching `l2encap`). A `src_pe` that is not a member excludes nothing.
- **Tenant isolation** — the I-SID is the top-level key; a MAC learned in one
  I-SID is invisible to every other. A flood or MAC-move in tenant A can never
  affect tenant B.
- **Ageing** — `tick(now)` reclaims dynamic entries older than
  `Options.aging_ticks`; an expired MAC reverts to unknown-unicast (floods
  again). `forward`/`lookup` already treat an over-age entry as a miss, so `tick`
  is memory reclamation only — forwarding is correct between ticks. A **static**
  entry (`learnStatic`) is never aged and is not overwritten by dynamic learning.

## MAC-move & capacity (the DoS bound)

- **MAC move** — re-learning a MAC now seen from a different PE updates the entry
  in place (last-writer-wins / accept-move); it is one entry, not two.
- **MAC-flood bound** — the learning table is capped **per tenant** by
  `Options.max_macs_per_isid`. When a tenant's FDB is full, `learn` first
  reclaims that tenant's expired entries; if still full a *new* MAC is rejected
  (`error.FdbFull`) — learning fails closed, existing entries untouched, and the
  unlearned MAC just forwards as unknown-unicast (floods), exactly as a real
  bridge degrades to flooding when its CAM fills. `max_isids` and
  `max_pes_per_isid` similarly bound the I-SID count and per-I-SID membership.
  Total worst-case memory is `max_isids × max_macs_per_isid` FDB entries plus
  `max_isids × max_pes_per_isid` membership entries — never unbounded.

## Time-injection contract

The table never reads a clock. Every entry point that ages state takes a
caller-supplied monotonic `now: Time` (abstract ticks in the caller's own unit;
`aging_ticks` is in the same unit). Given the same `(ops, now)` stream the table
yields the same decisions on every run, and every flood set is in ascending PE-id
order — both pinned by permanent tests.

## API

- `Table.init(alloc, options) Table` / `deinit()` — `Options` carries the caps
  (`max_isids`, `max_pes_per_isid`, `max_macs_per_isid`) and `aging_ticks`.
- `addMember(isid, pe) !void` / `removeMember(isid, pe)` / `isMember(...) bool` /
  `memberCount(isid) usize` — control-plane-populated membership.
- `learn(isid, mac, pe, now) !void` — dynamic learning (refresh + accept-move);
  `learnStatic(isid, mac, pe) !void` — pinned, never-aged; `forget(isid, mac)
  bool` — delete.
- `lookup(isid, mac, now) ?PeId` — the PE a known unicast would take, or null.
- `forward(isid, dst, src_pe, now, out) !Decision` — the forward decision;
  `replicationSet(isid, src_pe, out) ![]const PeId` — the split-horizon set
  directly, for a pre-classified BUM frame.
- `tick(now)` — reclaim aged entries. `fdbCount(isid)` / `isidCount()` — sizes.
- `isBroadcast(mac)` / `isMulticast(mac)` / `isBumAddress(dst)` — pure BUM
  classification helpers.

## Test

```
zig build test-l2forward
```

Unit tests cover BUM classification (broadcast/multicast/unicast); known-unicast
learn→forward and its unknown-unicast fallback; split-horizon flood
(`{2,3,4}` src 3 → `{2,4}`, and a non-member source excluding nothing); tenant
isolation (a MAC in I-SID A is unknown in B); MAC move (last-writer-wins);
ageing (fresh at the boundary, gone past it, `tick` reclaims, re-learn
refreshes) and static entries; the per-tenant MAC-flood bound (`FdbFull` after a
reclaim attempt, existing entries unaffected) plus I-SID/member caps;
determinism (identical `(ops, now)` → identical decisions, insertion-order-
independent sorted flood set); a permanent positive-control test proving a flood
set that *keeps* the source PE contradicts split-horizon; and a leak check
(`testing.allocator`) that `deinit` frees every nested map. Green in Debug and
`-Doptimize=ReleaseFast`.

Provenance: clean-room from public specifications (IEEE 802.1D, IEEE 802.1ah,
IEEE 802.1aq SPB, EVPN RFC 7432) — no third-party source or dissector consulted
or copied. No `/NOTICE` entry needed (spec citations live in SPEC.md). License:
MIT.
