# pbb

IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC) encapsulation codec: wrap a
customer Ethernet frame so it rides a **real Ethernet** provider backbone,
addressed by backbone MACs (B-DA/B-SA), optionally VLAN-tagged on the backbone
(B-Tag / B-VID), with the 802.1ah **I-TAG** carrying the 24-bit **I-SID** service
instance and the relocated customer addresses — and decode it back. This is the
real-Ethernet SPB (802.1aq) data-plane encapsulation. Pure, bounds-checked decode
of untrusted link bytes; no network, no clock, and no allocation on the decode
path.

**Status:** codec complete · offline golden/property/fuzz verified · FCS,
stacked I-TAGs, and customer-tag parsing deferred (see SPEC).

Derived metadata (canonical source: `pub const meta` in `src/root.zig`):
`any · codec · reentrant` · model-after IEEE 802.1ah (802.1Q-2014 clause 9.7 /
clause 25/26) · deps: none (std only).

## Contrast with `l2encap`

`pbb` and the sibling [`l2encap`](../l2encap/README.md) solve the same problem —
carry a tenant's opaque Ethernet frame across a shared fabric keyed by a 24-bit
I-SID — for two different backbones:

| | `pbb` (this module) | `l2encap` |
|---|---|---|
| Backbone | real Ethernet (no tunnel) | encrypted WireGuard tunnel |
| Backbone addressing | **B-DA / B-SA MACs + optional B-Tag/B-VID** | none — WireGuard peer identity addresses the tunnel |
| Header size | 30 B (untagged) / 34 B (B-Tagged) + payload | lean 8 B + payload |
| Tenant key | 24-bit I-SID | 24-bit I-SID (same width — the two map 1:1) |
| Format | IEEE 802.1ah standard | custom versioned over-WG layout |

`pbb` must address the backbone with real MACs because a real Ethernet core has
no tunnel to do it; `l2encap` deliberately drops them because WireGuard already
supplies transport addressing and crypto. They agree on the I-SID so a fabric can
translate between a WG edge and a real-Ethernet edge.

## Frame layout

The backbone frame, in order (the FCS is a frame-level trailer, out of scope):

```
 B-DA   6   backbone destination MAC
 B-SA   6   backbone source MAC
 B-Tag  4   OPTIONAL 802.1ad S-Tag: TPID 0x88A8 + TCI(PCP:3, DEI:1, B-VID:12)
 I-TAG      EtherType 0x88E7 (2)
            I-TCI (4): I-PCP:3 | I-DEI:1 | UCA:1 | Res:3 | I-SID:24
            C-DA (6)  encapsulated customer destination MAC
            C-SA (6)  encapsulated customer source MAC
 customer data   opaque: customer EtherType / C-VLAN tags / payload
```

**The I-TAG includes the encapsulated customer addresses.** Per 802.1Q clause
9.7 the customer frame's own DA/SA are *relocated into* the I-TAG (fields `c_da`
/`c_sa`), appearing **once** on the wire. The `customer_data` argument/slice is
therefore everything the customer frame carries *after* its own DA/SA (its
EtherType, any C-VLAN/S-VLAN tags, and payload), carried opaque. A caller holding
a *complete* customer Ethernet frame splits its first 12 bytes into `c_da`/`c_sa`
and passes the rest as `customer_data`; a receiver reassembles the full frame by
prepending `c_da`/`c_sa` to the decoded `customer_data`.

**The optional B-Tag** is detected on decode by its TPID: a `0x88A8` at the tag
region (right after the B-MACs) means a B-Tag is present (4 octets consumed, then
the `0x88E7` I-TAG EtherType must follow); a `0x88E7` there means the frame is
untagged on the B-VLAN and the I-TAG starts immediately; anything else is a typed
error.

## Untrusted-decode guarantees

`decode` consumes bytes straight off an untrusted link. Every field is
bounds-checked before it is read, and it allocates nothing (the `customer_data`
result is a subslice of the input). A truncated frame → `Truncated`; a
tag-region EtherType that is neither the B-Tag TPID nor the I-TAG EtherType →
`UnexpectedEtherType`; a B-Tag not followed by the I-TAG EtherType →
`MissingITag`. Reserved I-TCI bits are **ignored** on receipt (the IEEE format
mandates transmit-as-0, ignore-on-receipt) — this is the one deliberate
difference from `l2encap`, whose own versioned header *rejects* reserved bits.
See SPEC.md for the full threat model.

## API

```zig
const pbb = @import("pbb");

const fields: pbb.Fields = .{
    .b_da = .{ 0x10, 0, 0, 0, 0, 0xBB }, .b_sa = .{ 0x10, 0, 0, 0, 0, 0xAA },
    .b_tag = .{ .pcp = 3, .dei = false, .vid = 100 }, // or null = untagged B-VLAN
    .i_pcp = 5, .i_dei = false, .uca = true, .i_sid = 0x000123,
    .c_da = .{ 0, 0x11, 0x22, 0x33, 0x44, 0x55 },
    .c_sa = .{ 0, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE },
};

// Zero-alloc caller-buffer encode (customer_data = bytes after the customer DA/SA):
var buf: [1600]u8 = undefined;
const wire = try pbb.encode(fields, customer_data, &buf);

// Or allocate:
const owned = try pbb.encodeAlloc(allocator, fields, customer_data);
defer allocator.free(owned);

// Decode untrusted link bytes:
const dec = try pbb.decode(wire);       // pbb.DecodeError!Decoded
_ = dec.fields.i_sid;                    // u24 tenant id
_ = dec.fields.uca;                      // Use-Customer-Addresses bit
_ = dec.fields.b_da; _ = dec.fields.c_sa;// backbone / customer MACs
_ = dec.fields.bvid();                   // ?u12 — flattens the optional B-Tag
_ = dec.fields.hasBTag();                // bool
_ = dec.customer_data;                   // opaque bytes after the I-TAG
```

`Fields` exposes the I-SID, UCA, and all four MACs as public fields (idiomatic
Zig accessors); `bvid()` and `hasBTag()` flatten the optional B-Tag.
`encodedLen(fields, len)` / `headerLen(has_btag)` size a buffer.

## Verify

```
zig build test-pbb                       # Debug
zig build test-pbb -Doptimize=ReleaseFast
zig fmt --check modules/pbb
```

Provenance: clean-room from the IEEE 802.1ah / 802.1Q-2014 public standard — no
NOTICE entry needed (a public spec is not a copyrightable work; no third-party
source was ported into this codec). Two of the golden frames are hand-assembled
per the spec; a third is this module's own `encode()` output, independently
cross-checked against Wireshark 4.6.4's real IEEE 802.1ah dissector offline
(`scripts/dissect.py`, sharkd — no capture, no network needed). Wireshark
confirmed the I-TCI/B-TCI bit layout, the C-DA/C-SA relocation, and that its own
dissector recurses correctly into the encapsulated customer frame at exactly the
offset this codec treats as the boundary. See SPEC.md for the design, threat
model, and the one naming ambiguity ("UCA" vs Wireshark's "NCA") that check
turned up.
