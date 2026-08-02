# pbb — spec

Design + threat notes for auditors. Usage, API and the field-by-field wire
diagram: see [README.md](README.md) and the `src/root.zig` doc comments.
Attribution/provenance: see `/NOTICE` — none needed here (clean-room from the
public IEEE 802.1ah / 802.1Q-2014 standard; a public spec is not a copyrightable
work, and no third-party source was ported into this codec — the Wireshark
cross-check below is a behaviour comparison against `encode()`'s own output,
not a port).

## What it is

A stateless codec for the IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC)
encapsulation — the real-Ethernet counterpart to the lean over-WireGuard
[`l2encap`](README.md#contrast-with-l2encap). No I/O, no clock, and **no
allocation on the decode path**: `decode` returns the customer bytes as a
subslice of the input, so it cannot, by construction, allocate more than its
input. Concurrency `.reentrant` (no shared state).

## Frame format (verified against the standard)

Reference: **IEEE 802.1Q-2014 clause 9.7 (I-TAG) and clauses 25/26 (PBB)**. The
backbone frame, in wire order:

| # | field | octets | notes |
|---|-------|--------|-------|
| 1 | B-DA | 6 | backbone destination MAC |
| 2 | B-SA | 6 | backbone source MAC |
| 3 | B-Tag | 4 (optional) | 802.1ad S-Tag: TPID `0x88A8` + B-TCI |
| 4 | I-TAG EtherType | 2 | `0x88E7` |
| 5 | I-TCI | 4 | see bit table below |
| 6 | C-DA | 6 | encapsulated customer destination MAC — **inside the I-TAG** |
| 7 | C-SA | 6 | encapsulated customer source MAC — **inside the I-TAG** |
| 8 | customer data | * | opaque: customer EtherType / C-VLAN tags / payload |

The FCS is a frame-level trailer and is **out of scope** (deferred list).

### I-TCI bit order (the crux field)

The 4-octet I-TAG control information, most-significant bit first:

| bits | field | width | |
|------|-------|-------|--|
| 31..29 | I-PCP | 3 | priority code point |
| 28 | I-DEI | 1 | drop-eligible indicator |
| 27 | **UCA** | 1 | Use Customer Addresses |
| 26..24 | Res | 3 | reserved — transmit 0, **ignore on receipt** |
| 23..0 | **I-SID** | 24 | backbone service instance identifier |

So the first I-TCI octet is `PCP<<5 | DEI<<4 | UCA<<3 | Res`, and the remaining 3
octets are the big-endian I-SID. Getting UCA/DEI adjacency or the I-SID's 24-bit
window wrong is the classic 802.1ah bug; the module pins both with a byte-exact
golden, an isolated I-TCI-octet assertion, and two permanent positive-control
tests (a UCA↔DEI swap and an I-SID-read-from-the-wrong-3-bytes both go red).

### B-TCI bit order

The 2-octet B-Tag control information (a standard 802.1Q TCI): `PCP<<13 | DEI<<12
| B-VID`, i.e. PCP(3) | DEI(1) | VID(12), big-endian.

### Encapsulated customer addresses live *inside* the I-TAG

Per clause 9.7 the I-TAG structure formally contains C-DA and C-SA: PBB
**relocates** the customer frame's own destination/source MACs into the I-TAG
rather than leaving them at the front of the payload, so the customer addresses
appear exactly **once** on the wire. This module models that faithfully:
`c_da`/`c_sa` are `Fields`, and the `customer_data` argument/slice is everything
the customer frame carries *after* its own DA/SA. This is the chosen layout (not
"C-DA/C-SA simply follow the I-TAG as separate framing") because it is what the
standard specifies and it avoids carrying the customer MACs twice. A caller with a
complete customer Ethernet frame splits its first 12 bytes into `c_da`/`c_sa`; a
receiver prepends them to `customer_data` to rebuild it.

## Design decisions (judgement calls)

- **Encapsulated MACs as explicit `Fields`, not opaque payload.** Because the
  standard puts C-DA/C-SA inside the I-TAG, modelling them as `Fields` (rather
  than as the first 12 bytes of `customer_data`) matches the wire exactly and
  keeps `customer_data` a pure opaque remainder. This differs from `l2encap`,
  whose `customer_frame` is the *whole* opaque frame including its addresses —
  correct there, because `l2encap` does not relocate anything.
- **B-Tag presence by TPID, not a length/flag.** Decode reads the 2-octet
  EtherType right after the B-MACs: `0x88A8` ⇒ B-Tag present (consume 4, require
  `0x88E7` next); `0x88E7` ⇒ untagged, I-TAG starts here; anything else ⇒
  `UnexpectedEtherType`. This is exactly how a real bridge disambiguates and adds
  no non-standard signalling.
- **Reserved I-TCI bits are ignored, not rejected.** The IEEE format mandates
  transmit-as-0 / ignore-on-receipt, so `decode` fails **open** on reserved bits
  (and `encode` always writes 0). This is a deliberate divergence from
  `l2encap`, whose *own* versioned header rejects reserved bits to close a covert
  channel — `l2encap` can be strict because it owns its format; `pbb` must
  interoperate with a published one.
- **I-SID width = `u24`.** Matches the standard's 24-bit I-SID and `l2encap`'s
  I-SID, so the type makes an out-of-range value unpresentable and the two
  encapsulations map 1:1.
- **Accessors.** The I-SID, UCA and all four MACs are public `Fields` (idiomatic
  Zig, as in `l2encap`); `bvid()` and `hasBTag()` are added only where they earn
  their keep by flattening the optional B-Tag.

## Threat model / untrusted decode

`decode` consumes bytes straight off an untrusted link (a hostile or buggy peer,
or an injected frame). Every field is bounds-checked before it is read and the
decoder fails closed on structural errors:

- **Truncation:** checked before each field group — the B-MACs + tag-region
  EtherType (14), then (if B-Tagged) the B-TCI + next EtherType, then the full
  I-TAG (EtherType + I-TCI + C-DA + C-SA). Any shortfall → `Truncated`. Tested at
  **every** length below a full untagged frame and below a full B-Tagged frame.
- **Wrong tag-region EtherType:** neither `0x88A8` nor `0x88E7` after the B-MACs
  → `UnexpectedEtherType`.
- **B-Tag without an I-TAG:** a `0x88A8` B-Tag not followed by `0x88E7` →
  `MissingITag` (fail closed rather than best-effort parsing an unknown layout).
- **No over-read / no over-allocate:** `decode` allocates nothing; `customer_data`
  is a subslice strictly within the input (`ptr`+`len` asserted in the fuzz
  target). There is no length field to induce a large allocation from a small
  buffer — a malformed frame is rejected cheaply.
- **Reserved bits:** ignored (see above) — not a rejection surface, per spec.

The standing regression is the `std.testing.fuzz` target over `decode`
(truncated, wrong-EtherType, B-Tag with/without a following I-TAG, arbitrary
length and bytes), asserting only never-panic + customer-slice-within-input.

**Not a confidentiality/authenticity boundary.** The header is plaintext on the
backbone; PBB itself provides no per-frame crypto. Any such protection is a
separate layer (802.1AE MACsec on the backbone, or the WireGuard tunnel in the
`l2encap` variant) — this codec does not add, and does not claim, authentication.

## Deliberately deferred (out of scope by design, not oversight)

- **FCS** — the frame-level CRC trailer is added/checked by the MAC/NIC layer,
  not this codec.
- **Multiple stacked I-TAGs** — one I-TAG per frame; nested backbone service
  layering is out of scope.
- **Customer-tag parsing (C-VLAN / S-VLAN inside `customer_data`)** — the carried
  customer bytes are opaque; mapping a customer 802.1Q VID to an I-SID is a
  provisioning decision above this codec.
- **802.1ah management / OUI-scoped TLVs** and any control-plane signalling.
- **Forwarding / FDB / MAC learning** — backbone next-hop selection and the
  B-MAC/C-MAC learning state live in `l2forward`; this codec only frames bytes.
- **B-MAC/C-MAC semantics** — group-address/multicast B-DA conventions, I-SID→
  B-MAC derivation, and backbone MAC assignment are provisioning/forwarding
  concerns, not framing.

## Verification

Offline only — no live-interop surface (no packet capture was available). Two
byte-exact golden KATs (full B-Tagged frame + untagged-B-VLAN variant) are
hand-assembled field-by-field per the IEEE spec; a third golden is externally
anchored: `encode()`'s own output for a frame whose encapsulated customer frame
carries its own 802.1Q C-VLAN tag was fed through Wireshark 4.6.4's real IEEE
802.1ah dissector offline (`scripts/dissect.py`, sharkd — no capture, no
network), and the frozen bytes plus the quoted Wireshark output live in
`src/root.zig`. Wireshark independently confirmed the B-TCI and I-TCI bit
order (including bit 27), the 24-bit I-SID window, C-DA/C-SA placement, the
0x88E7 ethertype, and — the sharpest check of the encapsulation boundary —
that its own dissector recurses cleanly through B-Tag → I-Tag → the
encapsulated frame's own tag → IPv4 → data, which only works if
`customer_data` starts exactly where this codec says it does. The one
disagreement that turned up was cosmetic: Wireshark's dissector names the same
bit `NCA` ("No Customer Addresses") where this module calls it `uca` ("Use
Customer Addresses") — see the naming note beside the golden in `src/root.zig`
for why that was left as an open, cited ambiguity rather than "fixed" on the
strength of one of two conflicting secondary sources.

`zig build test-pbb`: the three goldens above; an isolated I-TCI-octet
bit-field test; two permanent positive-control tests (UCA↔DEI swap,
wrong-3-byte I-SID); a 500-iteration seeded encode→decode property test (I-SID
incl. 0 and `max_isid`, B-Tag present/absent, UCA 0/1, empty..4 KiB customer
data); truncation-at-every-length for both frame shapes; wrong-EtherType and
B-Tag-without-I-TAG rejection; reserved-bit ignore-on-receipt; I-SID
tenant-isolation; encode buffer-too-small and caller-buffer≡alloc equivalence;
and the `std.testing.fuzz` target. Green in Debug and
`-Doptimize=ReleaseFast`; `zig fmt --check` clean.

## Backlog / deferred

No Fable-tier piece was needed: the frame is a clean-room layout from a published
standard and the codec is total over its decoded field space. The hard fabric
problems (loop-free BUM-tree reconvergence, designated-forwarder election) live in
the S1b `loopfree-reconv` / `df-elect` modules, which this codec feeds; forwarding
state lives in `l2forward`.

## Status

`any · codec · reentrant` · deps: none (std only) — canonical source is
`pub const meta` in `src/root.zig`.
