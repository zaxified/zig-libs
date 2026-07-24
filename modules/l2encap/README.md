# l2encap

A pure-Zig **tenant-tagged L2-over-tunnel encapsulation codec** for a
multi-tenant, encrypted L2VPN fabric. It wraps an opaque customer Ethernet frame
in a lean, versioned 8-byte header so that many isolated tenants' Layer-2 traffic
can share one encrypted WireGuard backbone between provider edges (PEs), and it
supplies the two pure per-frame forwarding decisions (TTL, split-horizon) a PE
needs. It is a codec only: no socket, no clock, no allocation on decode.

Status: **gap** — the S1b L2-over-WireGuard data plane needs a tenant tag + loop
backstop that neither WireGuard nor `ethfrag` provides; this fills exactly that
slot. Model + rationale below; full design/threat notes in
[SPEC.md](SPEC.md).

## Model-after

Modelled on three proven references, taken lean because the encrypted WireGuard
backbone already provides transport addressing and crypto:

- **802.1ah PBB I-TAG** — the 24-bit **I-SID** tenant service identifier is
  borrowed directly. But full PBB also carries backbone source/destination MACs;
  we drop those (WireGuard addresses the tunnel), which is the "lean over-WG"
  difference.
- **VXLAN / Geneve VNI** — same 24-bit tenant-scope width; interoperable mental
  model of "a numeric overlay id selects the tenant bridge domain".
- **SPB (IEEE 802.1aq) / TRILL** — the **ingress-PE id** + **TTL** are the
  source-nickname and hop-count that a shortest-path-bridging core uses for loop
  mitigation of BUM traffic.

## Header layout

Fixed 8-byte header, all multi-byte fields big-endian, followed by the opaque
customer frame:

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    version    |     flags     |            I-SID (24 bits)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      TTL      |       ingress PE id (16 bits) |  customer ... |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **version** (1 byte, = 1): unknown versions are rejected, so the format can
  evolve without old peers misparsing it.
- **flags** (1 byte): bit 0 = BUM (broadcast/unknown-unicast/multicast) vs
  unicast; bits 1..7 reserved and must be zero (strict decode).
- **I-SID** (24 bits): the tenant. The tenant-isolation key.
- **TTL** (1 byte): decremented per PE hop; 0-on-receipt is dropped.
- **ingress PE id** (16 bits): the PE that first encapsulated the frame; drives
  split-horizon.

There is deliberately **no payload-length field** — the customer frame is
everything after byte 8, so there is nothing to lie about at this layer;
carrier-level length/MTU integrity belongs to the downstream fragmenter.

## Loop prevention, split-horizon & tenant isolation

- **TTL** is the data-plane loop backstop: any transient loop dies after at most
  `initial_ttl` PE hops regardless of the control plane. A transit PE calls
  `decrementTtl` before forwarding; `TtlExpired` means drop.
- **Split-horizon** stops a PE re-delivering its own ingress-replicated BUM
  traffic: `droppedBySplitHorizon(fields, this_pe)` is true iff the frame is BUM
  **and** `ingress_pe == this_pe`. Unicast is never dropped by this rule; a BUM
  frame from any other PE is accepted.
- **Tenant isolation**: two frames that differ only in I-SID decode to two
  distinct tenants and never share a forwarding/MAC-learning domain — the I-SID
  is the only isolator this layer carries.

The ingress-PE id + TTL are the **necessary inputs** to loop mitigation, and TTL
alone bounds any loop to a finite length. Full loop-freedom of the BUM
distribution tree (reverse-path-forwarding check, tree computation, MAC
learning, actual replication) is a **control-plane** responsibility layered on
top — see [SPEC.md](SPEC.md)'s deferred list.

## Pipeline

The intended data path is **encapsulate → fragment → encrypt**:

```
customer frame ──l2encap.encode──▶ [hdr|frame] ──ethfrag.fragment──▶ chunks ──▶ wireguard
```

`encode` returns a plain `[]u8`; this module does **not** import `ethfrag` or
`wireguard` (separation of concerns) — the caller chains them.

## API

- `encode(fields, customer_frame, out) ![]u8` — zero-alloc, into a caller
  buffer; `encodedLen(payload_len)` sizes it.
- `encodeAlloc(allocator, fields, customer_frame) ![]u8` — owned-bytes variant.
- `decode(bytes) !Decoded` — `{ fields, payload }`; `payload` is a subslice of
  the input (no copy, no allocation). Truncated / wrong-version /
  reserved-bit-dirty input is a typed `DecodeError`, never a panic.
- `decrementTtl(fields) !Fields` — per-hop TTL step, `TtlExpired` on 0.
- `droppedBySplitHorizon(fields, this_pe) bool` — the split-horizon test.
- `looksLikeEthernet(payload) bool` — advisory-only payload sniff (`decode`
  never calls it; the customer frame is opaque by default).

## Test

```
zig build test-l2encap
```

A hand-verified golden byte layout pins the wire format field-by-field; a
500-iteration seeded property test round-trips encode → decode (I-SID incl. 0 and
max, both frame types, empty..4 KiB payloads); a permanent positive-control test
proves the golden catches a little-endian I-SID bug; semantics tests cover TTL
drop-at-zero, split-horizon, and I-SID isolation; and a `std.testing.fuzz` target
drives hostile bytes at `decode` asserting never-panic and payload-within-input.
Green in Debug and `-Doptimize=ReleaseFast`.

Provenance: clean-room from public specifications (IEEE 802.1ah PBB I-TAG,
RFC 7348 VXLAN, RFC 8926 Geneve, IEEE 802.1aq SPB) — no third-party source or
dissector consulted or copied. No `/NOTICE` entry needed (spec citations live in
SPEC.md). License: MIT.
