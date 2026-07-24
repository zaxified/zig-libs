# spbfib

SPB (IEEE 802.1aq / RFC 6329) forwarding addressing: the two pure address
computations an SPBM backbone node needs on top of the already-computed
`isis-spf` route table. The **unicast** counterpart to the multicast `bumtree`.

## What it computes

**Part A — the unicast B-MAC FIB.** `isis-spf`'s `RouteTable` maps a destination
*system-id* to a next-hop *system-id*. But the SPBM data plane forwards on the
destination's **backbone MAC (B-MAC)**, not its system-id: the ingress backbone
edge bridge sets the frame's DA to the *destination node's* B-MAC, and every
transit node forwards on that DA **unchanged** (the DA is not rewritten
hop-by-hop). Given the route table and a caller-supplied **system-id → B-MAC
map**, `Fib.build` re-keys every reachable destination by its **destination
B-MAC** and resolves the next-hop system-id to the **next-hop's B-MAC** (which
selects the egress adjacency, not the DA). `Fib.lookup(dest_bmac)` is an O(log n)
binary search over the sorted entries.

- **One path per destination, no per-flow ECMP.** SPB installs exactly the single
  congruent ECT path `isis-spf` already selected; there is no per-flow hashing at
  the data plane. (The 16 ECT algorithms spread paths across I-SIDs / B-VIDs, not
  within a flow.)
- **Skip rules.** A destination whose B-MAC is not in the map is skipped; a
  reachable destination whose *next hop* has no B-MAC is skipped too (its egress
  adjacency is unresolvable). The FIB never carries an entry it could not forward.
- **Local delivery.** The local self route (metric 0) becomes an entry with
  `local = true` and `next_hop_bmac == dest_bmac`.

**Part B — the SPBM group multicast-DA.** A BUM frame for an I-SID uses a group
destination B-MAC built from the source node's 20-bit **SPSourceID** and the
24-bit **I-SID** — the very DA whose per-source distribution tree `bumtree`
computes. `groupDa(spsourceid, isid)` builds it; `parseGroupDa` is the exact
inverse. Bit layout (RFC 6329 §4.4, Figure 1):

```text
    M L TYP
  +-+-+-+-+-------+---------------+---------------+---------------+
  |1|1|0|0|SPSrcMS|  SPSrc[8:15]  |  SPSrc[0:7]   | I-SID[16:23]  |  octets 0..3
  +-+-+-+-+-------+---------------+---------------+---------------+
  | I-SID[8:15]   |  I-SID[0:7]   |                                  octets 4..5
  +---------------+---------------+
```

The figure numbers bits least-significant-first within each octet, so the
leftmost **M** cell is the canonical `0x01` bit of octet 0 — the ordinary
Ethernet I/G (group) bit. Concretely `octet0 = M(0x01) | L(0x02) | (SPSrcMS<<4)`
(TYP `0x0C` left 0), octets 1–2 carry the rest of the SPSourceID, and octets 3–5
carry the I-SID (big-endian, the low 24 bits). Verified byte-for-byte against
RFC-6329-derived worked examples: `groupDa(0x04001, 200) == 03:40:01:00:00:C8`
and `groupDa(0xE8607, 0x0006E9) == E3:86:07:00:06:E9`. See `SPEC.md` for the
field-by-field derivation and the residual bit-order note.

**Model-after:** IEEE 802.1aq (SPBM) unicast B-MAC FIB + the RFC 6329 §4.4 group
multicast-DA construction. Clean-room from the public standard.

**Status:** `any · util · single_owner` · deps: `isis-spf` (which owns the SPF /
ECT route table this consumes) — canonical metadata is `pub const meta` in
`src/root.zig`. This module parses no TLVs and recomputes no SPF: the
system-id→B-MAC map and each node's SPSourceID are inputs the caller extracts
from the SPB sub-TLVs (`isis/spb`).

## Pairing with `bumtree`

`bumtree` is the **multicast** half of SPBM control-plane forwarding — the
per-source, member-pruned BUM distribution tree + RPF check. `spbfib` is the
**unicast** half — the destination-B-MAC FIB — plus the group-DA construction
that names the multicast trees `bumtree` distributes. Both are pure computations
over the `isis-spf`/`spf-ect` stack; neither does I/O.

## Usage

```zig
const spf = @import("isis-spf");
const spbfib = @import("spbfib");

// A route table from isis-spf (dest system-id → next-hop system-id + metric).
var table = try spf.compute(gpa, &lsdb, local_system_id, now);
defer table.deinit();

// The caller extracts each node's B-MAC from its SPBM-SI sub-TLV (isis/spb).
const bmac_map = [_]spbfib.BmacEntry{
    .{ .system_id = a, .b_mac = a_bmac },
    // …
};

var fib = try spbfib.Fib.build(gpa, &table, &bmac_map);
defer fib.deinit();

if (fib.lookup(dest_bmac)) |e| {
    // forward toward e.next_hop_bmac (egress adjacency); the frame DA stays dest_bmac
}

// The group DA for a BUM frame this node sources on an I-SID:
const da = spbfib.groupDa(my_spsourceid, isid);
```

`Fib.build` uses correct destination-B-MAC keying; `Fib.buildWith(..., .{
.key_by_next_hop_bmac = true })` mis-keys by the next hop and exists only for the
positive-control test.

## Upstream

The `isis-spf.RouteTable` is produced by `isis-spf` (LSDB → two-way-checked
topology → `spf-ect` Dijkstra + ECT tie-break → dest→next-hop table). This module
consumes that table read-only.

## Deferred (out of scope by design — see `SPEC.md`)

- **B-MAC / SPSourceID extraction from TLVs** — the caller decodes the SPBM-SI
  and SPB-Instance sub-TLVs (`isis/spb`) and hands this module the resolved map
  and IDs.
- **Multiple B-VIDs / the 16 ECT algorithm set** — one congruent path from
  `isis-spf`'s single deterministic ECT selection.
- **Line-rate forwarding** — this returns a FIB, not programmed hardware state.
- **I-SID service membership** — which local ports belong to a service is
  `l2forward`'s job.

## Verify

```
zig build test-spbfib                          # Debug
zig build test-spbfib -Doptimize=ReleaseFast   # ReleaseFast
```

Provenance: clean-room from IEEE 802.1aq / RFC 6329; no third-party source or
implementation ported or studied — no `NOTICE` entry (see `/NOTICE` and
`CONVENTIONS.md` §5).
