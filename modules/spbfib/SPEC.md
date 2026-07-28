# spbfib — spec

Design + threat notes for auditors. Usage, API and the field contract: see
[README.md](README.md) and the `src/root.zig` doc comments.
Attribution/provenance: see `/NOTICE` — none needed here (clean-room from the
public IEEE 802.1aq / RFC 6329 standard; a public spec is not a copyrightable
work, and no third-party source or implementation was ported or studied).

## What it computes

Two pure SPBM (IEEE 802.1aq) address computations over the already-computed
`isis-spf` route table, with no I/O, no TLV parsing, and no SPF of its own:

- **Part A — the unicast B-MAC FIB**: re-key `isis-spf`'s `dest system-id →
  next-hop system-id` table into `dest B-MAC → { next_hop_bmac,
  next_hop_system_id, metric, local }`.
- **Part B — the SPBM group multicast-DA**: `groupDa(spsourceid, isid)` and its
  inverse `parseGroupDa`.

## Part A — the unicast B-MAC FIB

### Why B-MAC keying

In SPBM the ingress backbone edge bridge encapsulates the customer frame in a
backbone MAC-in-MAC header whose **B-DA is the destination node's B-MAC**. That
DA is *not* rewritten hop-by-hop; every transit node's backbone FDB is keyed on
it and forwards congruently. So the data-plane forwarding key is the
**destination's** B-MAC, while `isis-spf` speaks in system-ids. The next hop's
B-MAC does **not** go into the frame DA — it identifies the adjacent bridge, i.e.
which egress adjacency the FDB entry points at. Hence each `Entry` carries the
destination B-MAC as its key and the next-hop B-MAC separately.

### Algorithm

1. Build `system-id → B-MAC` (`std.AutoHashMapUnmanaged`) from `bmac_map`, first
   binding wins on a duplicate (so the map is order-independent). Used only for
   point lookups — never iterated — so it contributes no nondeterminism.
2. Iterate `route_table.routes` (already sorted by destination system-id). For
   each route:
   - resolve `dest_bmac`; if absent → **skip** (destination B-MAC unknown);
   - the self route (`metric == 0`) → a `local` entry with `next_hop_bmac ==
     dest_bmac`;
   - otherwise resolve the next hop's B-MAC; if absent → **skip** (egress
     unresolvable).
3. Sort the entries by key B-MAC, ties broken by destination system-id, giving a
   total, deterministic order and an O(log n) binary-search `lookup`.

`metric == 0` uniquely identifies the self route because `isis-spf` clamps every
edge weight to ≥ 1, so only the SPF root has distance 0.

### Skip-rule rationale

An entry the forwarder cannot act on is worse than an absent one (it would either
forward to nowhere or need a runtime null-check on the hot path). Both unknown-
B-MAC cases therefore drop the route rather than emit a partial entry;
`next_hop_bmac` stays non-optional. This is a policy choice, documented on
`buildWith`, not a spec requirement — a caller that would rather see incomplete
entries can join the raw `route_table` with its own map.

### One path, no per-flow ECMP

SPB is not IP: it does not hash a flow across equal-cost next hops. `isis-spf`
(via `spf-ect`'s deterministic ECT tie-break) already picked exactly one
congruent path per destination, and this module installs that one. The 16 ECT
algorithms in 802.1aq provide path *diversity across* I-SIDs/B-VIDs (each B-VID
maps to one ECT algorithm), never a per-flow spread within a single B-VID. So a
FIB with one entry per destination is correct, not a simplification.

### Bounds / determinism

Allocation is bounded by the route count: the transient `system-id → B-MAC` map
(freed on return) and the entries array (≤ `routes.len`). No recursion, no
unbounded loop. The result is byte-identical across `bmac_map` orderings and
repeated builds. `Fib.deinit` frees `entries`; a `testing.allocator` run
leak-checks it.

## Part B — the SPBM group multicast-DA

### Field layout (RFC 6329 §4.4, Figure 1)

```text
    M L TYP
  +-+-+-+-+-------+---------------+---------------+---------------+
  |1|1|0|0|SPSrcMS|  SPSrc[8:15]  |  SPSrc[0:7]   | I-SID[16:23]  |  octets 0..3
  +-+-+-+-+-------+---------------+---------------+---------------+
  | I-SID[8:15]   |  I-SID[0:7]   |                                  octets 4..5
  +---------------+---------------+
```

| Field | Bits | Placement | Value |
|---|---|---|---|
| **M** (I/G multicast) | 1 | octet 0, `0x01` | always 1 |
| **L** (locally administered) | 1 | octet 0, `0x02` | always 1 |
| **TYP** (SPSourceID type) | 2 | octet 0, `0x0C` | `00` (only type defined) |
| **SPSrcMS** | 4 | octet 0 high nibble, `0xF0` | top 4 bits of SPSourceID |
| **SPSourceID** rest | 16 | octets 1–2, big-endian | bits [0:15] |
| **I-SID** | 24 | octets 3–5, big-endian | the full 24-bit service id |

Total: 4 flag/type bits + 20-bit SPSourceID + 24-bit I-SID = 48 bits, exactly one
MAC address. So `octet0 = 0x03 | ((SPSourceID >> 16) << 4)`.

### The bit-order subtlety (why the M bit is `0x01`, not `0x80`)

RFC 6329's Figure 1 draws the leftmost cell as **M**, which naively could read as
the most-significant bit (`0x80`) of octet 0. It is not. The RFC's own note under
the figure states: *"the index numbering from less significant bit to more
significant bit within a byte … gives the wire order of the bits … the IEEE
convention for number representation reverses the bits within an octet compared
with IETF practice."* So the leftmost drawn bit is the **least**-significant
(`0x01`) bit of the octet as written in canonical hex — which is precisely the
ordinary Ethernet I/G bit (a real multicast MAC, e.g. `01:00:5e:…`, has that bit
set). Reading M as `0x80` would produce a non-multicast address that hardware
would not treat as a group DA. This is the one genuine ambiguity in the layout,
and it is resolved unambiguously by the RFC note **and** by two independent
worked examples that both begin the flag byte at `0x03`:

- I-SID 200 (`0xC8`), SPSourceID `0x04001` → `03:40:01:00:00:C8`.
- SPSourceID `0xE8607`, I-SID `0x0006E9` → `E3:86:07:00:06:E9` (first octet
  `0xE3` = `1110` SPSrcMS · `00` TYP · `1` L · `1` M).

`groupDa` reproduces both byte-for-byte in the tests, and `parseGroupDa`
validates the flag nibble (`da[0] & 0x0F == 0x03`) before decoding, rejecting any
DA whose M/L/TYP bits are not the SPBM group pattern.

### Total / inverse

`groupDa` is a total function (every input yields a well-formed group +
locally-administered MAC); `parseGroupDa(groupDa(sp, id)) == .{ sp, id }` for the
whole domain (tested at the field extremes). No allocation, no failure mode.

## Verification

Offline only — pure logic, no live-interop surface. `zig build test-spbfib`
is green in Debug + `-Doptimize=ReleaseFast`:

**Unicast FIB**
- **Golden line A—B—C** — a real `isis-spf.RouteTable` (`{a,a,0}`, `{b,b,10}`,
  `{c,b,20}` — the exact routes `isis-spf.compute` emits for that line, mirroring
  `isis-spf`'s own golden test) + a system-id→B-MAC map; asserts the exact
  `dest B-MAC → { next_hop_bmac, next_hop_system_id, metric, local }`, including
  the multi-hop destination C whose next-hop B-MAC (B's) ≠ its dest B-MAC.
- **Unknown destination B-MAC** — a reachable dest absent from the map is skipped,
  no crash.
- **Unknown next-hop B-MAC** — a reachable dest whose next hop has no B-MAC is
  skipped (the documented egress-unresolvable rule).
- **Determinism** — a shuffled `bmac_map` yields a byte-identical, key-sorted FIB.
- **Duplicate binding** — first B-MAC for a system-id wins, order-independently.
- **Degenerate** — empty route table → empty FIB; local-only → one `local` entry.
- **Positive control** — `key_by_next_hop_bmac = true` mis-keys the multi-hop
  destination under its next hop, so a lookup by its own DA returns null while the
  correct build finds it. Permanent proof that destination-B-MAC keying is
  load-bearing.

**Group multicast-DA**
- **Exact bytes** — both RFC-6329-derived worked examples reproduced byte-for-byte
  (a test that fails if the SPSourceID or I-SID bits are mis-positioned).
- **Flag bits** — M (group) and L (local) set and TYP zero for any input.
- **Round-trip** — `parseGroupDa(groupDa(x)) == x` across the field extremes.
- **Distinctness** — distinct `(spsourceid, isid)` pairs (including ones differing
  only in the SPSrcMS nibble or only in an I-SID octet) map to distinct DAs.
- **Field isolation** — changing only the I-SID moves only octets 3–5; changing
  only the SPSourceID moves only octets 0–2.
- **Rejection** — `parseGroupDa` returns null for broadcast, all-zero, and an IPv4
  multicast DA (L clear).
- **Positive control** — a deliberately mis-placed construction (I-SID written
  where the SPSourceID belongs) differs from the correct DA.

`zig fmt --check` clean; `zig build check-catalog` green.

## Deliberately deferred (out of scope by design, not oversight)

- **B-MAC / SPSourceID extraction from TLVs** — the caller decodes the SPBM-SI
  (RFC 6329 §3.5.4) and SPB-Instance (§3.5.2) sub-TLVs via `isis/spb` and supplies
  the resolved map and IDs; this module takes them as inputs.
- **Multiple B-VIDs / the 16 ECT algorithm set** — one congruent path per
  destination from `isis-spf`'s single deterministic ECT selection; no per-B-VID
  FIB set and no per-flow ECMP.
- **Line-rate forwarding** — a FIB is returned, not programmed hardware state.
- **I-SID service membership** — which local ports belong to a service is
  `l2forward`'s job.
- **The multicast distribution tree itself** — that is `bumtree`; `spbfib` only
  constructs the group DA that names it.
