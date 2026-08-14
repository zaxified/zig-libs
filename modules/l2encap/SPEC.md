# l2encap — spec

Design + threat notes for auditors. Usage, API and the field-by-field wire
diagram: see [README.md](README.md) and the `src/root.zig` doc comments.
Attribution/provenance: see `/NOTICE` — none needed here (clean-room from public
specs: IEEE 802.1ah PBB I-TAG, RFC 7348 VXLAN, RFC 8926 Geneve, IEEE 802.1aq SPB;
a public spec is not a copyrightable work, and no third-party source or dissector
was ported or studied).

## Design & invariants

`l2encap` is a stateless codec plus two pure decision primitives. It has no I/O,
no clock, and — crucially — **allocates nothing on the decode path**: `decode`
returns the customer frame as a subslice of its input, so it cannot, by
construction, allocate more than its input (the property the untrusted-decode
threat model asks for). `encode` has a zero-allocation caller-buffer form
(`encode`) and an owned-bytes convenience wrapper (`encodeAlloc`), matching
`ethfrag`'s split between a pure `Header.encode` and an allocating `fragment`.
Concurrency is `.reentrant`: no shared state, safe if not shared.

### Why these fields, versus PBB / VXLAN / Geneve

The fabric is many isolated tenants' Ethernet frames riding one encrypted
WireGuard backbone between PEs. WireGuard already provides transport addressing
and confidentiality/authenticity, so the encapsulation only has to carry what
WireGuard does not:

| Field | Width | Borrowed from | Why here (and why not wider/narrower) |
|---|---|---|---|
| version | 8 bit | (own) | Lets a future v2 change everything after byte 0; unknown version fails closed. A whole byte is cheap and leaves clean room. |
| flags.bum | 1 bit | SPB BUM handling | One bit is all the split-horizon rule needs; B vs U vs M is recoverable from the customer frame's own destination MAC, so distinguishing them here would be redundant width. |
| I-SID | 24 bit | PBB I-TAG / VXLAN VNI / Geneve VNI | The exact convention of all three references. 16,777,216 tenants — far past any realistic single-fabric tenant count. No reason to widen; narrowing would break the familiar 24-bit overlay-id mental model. |
| TTL | 8 bit | SPB/TRILL hop count, IP TTL | 255 PE hops dwarfs any real fabric diameter; the field only has to bound loop lifetime, not count real distance. |
| ingress PE id | 16 bit | SPB SPSourceID / TRILL nickname | 65,536 PEs. The source nickname a shortest-path core uses to attribute BUM traffic; drives split-horizon. |

**What is deliberately dropped versus full PBB:** the 48-bit backbone source and
destination MAC addresses (B-SA/B-DA) and the B-VID. WireGuard's peer identity +
tunnel selection replace backbone MAC addressing entirely, so carrying it would
be dead weight. That single omission is the whole "lean over-WG" claim: an
`ethfrag`-sized 8-byte header instead of PBB's 22.

**No payload-length field.** Unlike `ethfrag` (whose reassembler *must* carry
offset/length), the customer frame here is simply "the rest of the buffer". That
removes an entire class of length-lie / teardrop-overrun bug at this layer — a
decoder cannot be told a length that disagrees with the bytes present, because it
is never told a length at all. Carrier-level length/MTU integrity is owned by the
downstream fragmenter (`ethfrag`), which is the correct separation of concerns.

## Loop prevention & split-horizon — precise semantics

Two mechanisms, both of which this module only *supplies the inputs and the
per-frame test* for; it never forwards, replicates, or learns.

1. **TTL (data-plane backstop).** The ingress PE stamps `initial_ttl`
   (`default_ttl` = 64 suggested). Each transit PE calls `decrementTtl` before
   forwarding; a frame that arrives with TTL 0 (`TtlExpired`) is dropped. This
   bounds *any* loop — including a transient control-plane inconsistency — to at
   most `initial_ttl` PE hops, with no dependence on the control plane being
   converged. It is the always-correct backstop, not the primary loop-avoidance
   mechanism.

2. **Split-horizon (BUM source reflection).** `droppedBySplitHorizon(fields,
   this_pe)` returns true iff the frame is BUM **and** its `ingress_pe` equals
   the local PE id. Semantics: a PE that ingress-replicated a BUM frame to the
   fabric recognizes its own source id if a copy is delivered back to it, and
   drops that copy rather than re-delivering to local attachment circuits or
   re-replicating it. This is the SPB "a bridge never forwards a BUM frame back
   toward its own source" rule expressed as a stateless per-frame predicate.

### Honest scope of the loop claim (do not overclaim)

The ingress-PE-id split-horizon rule prevents exactly one case: **reflection**,
a BUM frame delivered back to its own originator. That is a narrower guarantee
than "split horizon", and the gap is not hypothetical.

**The failure mode it does not close, and which was ours.** The dominant loop
in a fully converged fabric was the **steady-state core relay**: a PE that
received a BUM frame *from the core* re-replicated it to every other member,
because `l2forward` returned *members − src_pe* for every BUM frame regardless
of where it came from. With N members, hop k carries `(N−1)(N−2)^(k−1)` copies
of one broadcast. `droppedBySplitHorizon` cannot recognise a single one of those
copies, and the reason is a property of this header: **`ingress_pe` is stamped
once at ingress and is preserved across `decrementTtl`**, deliberately, so that
the field keeps naming the *originator* rather than the previous hop. A third PE
therefore compares its own id against the originator's, never against the
relayer's, and the predicate is false for every relayed copy. Nothing about that
is a defect in this module — the alternative (rewriting `ingress_pe` per hop)
would destroy the reflection rule the field exists for — but it does mean the
split-horizon predicate is **not** a relay guard, and must not be described as
one. The relay is closed in `l2forward`, by classifying the frame's arrival
(core-received ⇒ `local_only`); see its SPEC, and the 4-PE composition test that
pins it.

(An earlier revision of this paragraph named only the *transient reconvergence*
loop as the residual risk, and that misdirected the reader: the dominant failure
mode was in the steady state, needed no reconvergence, no misconfiguration and
no malformed frame, and it was ours.)

**What is still not closed anywhere in the data plane:** a transient forwarding
loop among PEs during control-plane reconvergence, when member sets disagree.
That requires a loop-free BUM distribution tree and a reverse-path-forwarding
check, which are **control-plane** computations (the S1b `loopfree-reconv` /
SPB-tree work), not something a stateless codec can assert. The header's job is
to carry the *necessary inputs* (source id + hop count + BUM bit) to those
decisions; the TTL backstop guarantees that even a loop the control plane briefly
allows is finite. This division — codec supplies fields + local predicates,
control plane owns the tree — is intentional and is the reason the loop-freedom
proof lives in a different module, not here.

## Threat model / untrusted decode

`decode` consumes bytes straight off an untrusted tunnel (an attacker who can
inject into the WireGuard payload, or a buggy/hostile peer). Every field is
bounds-checked before it is read, and the decoder fails closed:

- **Truncation:** `< header_len` (8) bytes → `Truncated`, before any field
  read. Tested at every length 0..7 plus the exact-8 boundary.
- **Wrong/unknown version:** any version byte other than `version_current` (1),
  including the all-zero-buffer case (version 0) → `UnsupportedVersion`. A future
  format is never best-effort-parsed under the wrong rules.
- **Reserved-field smuggling:** any of the 7 reserved `flags` bits set →
  `InvalidHeader` (rejected, not masked) — closes a reserved-bit covert channel,
  matching `ethfrag`.
- **No over-read / no over-allocate:** `decode` allocates nothing; `payload` is a
  subslice strictly within the input (`ptr` and `len` asserted in the fuzz
  target). There is no length field to induce a large allocation from a small
  buffer.
- **Decision helpers never panic:** `decrementTtl` and `droppedBySplitHorizon`
  are total over all `Fields` values (every bit pattern of a decoded header is a
  valid `Fields`), so they cannot panic on adversarial input.

The standing regression is the `std.testing.fuzz` target over `decode`
(truncated, wrong-version, reserved-dirty, bit-flipped, arbitrary-length),
asserting only never-panic + payload-within-input.

**Not a confidentiality/authenticity boundary.** This header is plaintext inside
the tunnel; WireGuard provides the crypto. A frame with a spoofed I-SID or
ingress-PE id injected *inside* an authenticated WireGuard session is bounded by
the same fabric trust as any other in-tunnel byte — this codec does not add, and
does not claim, per-frame authentication (see deferred list).

## Deliberately deferred (out of scope by design, not oversight)

- **FIB / forwarding table** and the actual next-hop selection.
- **BUM replication** (ingress replication or P2MP tree fan-out) — this module
  only *classifies* a frame as BUM and supplies the split-horizon predicate.
- **Control plane** — I-SID↔tenant binding distribution, PE-id assignment,
  BUM-tree computation, reverse-path-forwarding check, adjacency/reconvergence
  (the S1b `df-elect` / `loopfree-reconv` / `liveness-hyst` modules).
- **MAC learning** and the customer-side bridging state.
- **VLAN-in-I-SID / QinQ mapping** — mapping a customer 802.1Q VID to an I-SID is
  a provisioning decision above this codec; the customer frame (tags and all) is
  carried opaque.
- **Fragmentation & encryption** — downstream (`ethfrag`, `wireguard`); this
  module hands them a plain `[]u8` and imports neither.
- **Per-frame authentication** beyond WireGuard's tunnel-level guarantees.

## Verification

Offline only — pure codec, no live-interop surface. `zig build test-l2encap`:
golden byte-layout KAT (BUM + unicast/I-SID-0/empty-payload variants) pinning
every field's offset and endianness; a 500-iteration seeded encode→decode
property test (I-SID incl. 0 and `max_isid`, both frame types, empty..4 KiB
payloads); a permanent positive-control test that reverses the I-SID bytes and
proves the golden/decode would go red on a little-endian bug; semantics tests for
TTL decrement + drop-at-zero, split-horizon (own-PE BUM dropped, other-PE BUM and
all unicast accepted), and I-SID isolation; encode buffer-too-small and
caller-buffer≡alloc equivalence; decode truncation-at-every-length,
wrong-version, and reserved-bit rejection; and the `std.testing.fuzz` target.
Green in Debug and `-Doptimize=ReleaseFast`; `zig fmt --check` clean.

### External-anchor investigation: kernel VXLAN/Geneve capture (2026-08-01, refuted)

An audit task asked whether the kernel's real VXLAN and Geneve encapsulation
(created in a throwaway unprivileged `unshare --user --net` namespace, a veth
pair as underlay so the frames are genuine off-the-wire traffic rather than a
loopback-local shortcut, a static ARP entry to avoid resolution flakiness) could
anchor this module's outer-header/VNI-placement/flags bytes against the kernel
instead of against our reading of RFC 7348 / RFC 8926. It was actually run — a
real `vxlan` interface (VNI 424242, i.e. `0x067932`) and a real `geneve`
interface (same VNI) were built and a frame captured off each via a plain
`AF_PACKET` socket (no `tcpdump`, so no `-Z` risk) — and it disproves its own
premise: **this module's 8-byte header is not VXLAN or Geneve on the wire**, so
there is nothing shared to anchor.

The real kernel bytes captured, decoded field-by-field:

```
VXLAN  (dst UDP 4789): 08 00 00 00 06 79 32 00
                        ^^ flags(I=1)  ^^^^^^ VNI=0x067932  ^^ reserved
                        byte0          bytes4-6            byte7
Geneve (dst UDP 6081): 00 00 65 58 06 79 32 00
                        ^^ ^^ ver/opt  ^^^^^ ^^^^^^ VNI=0x067932  ^^ reserved
                        |  proto-type=0x6558 (transparent Ethernet bridging)
                        ver=0,optlen=0
```

versus this module's own header (`writeHeader`, `src/root.zig`):

```
l2encap: 01 01 0A BB CC 40 12 34
         ^^ version  ^^^^^^^^ I-SID (bytes 2-4)  ^^ TTL  ^^^^^ ingress-PE (6-7)
            ^^ flags (byte 1, bum bit)
```

Both real encapsulations put the 24-bit VNI at **bytes 4‥6**, confirming the
"Model-after" table's claim that the 24-bit tenant-scope width is the real VXLAN
VNI / Geneve VNI convention (both, independently, big-endian) — that part of the
provenance claim is now kernel-verified, not merely RFC-read. But `l2encap`
carries the same-width **I-SID at bytes 2‥4**, has a **version byte** neither
protocol has, and has **no counterpart at all** for VXLAN's flags byte, Geneve's
ver/optlen/protocol-type bytes, or its own TTL/ingress-PE bytes in either real
protocol. Byte-for-byte, `l2encap` frames are not parseable by a VXLAN or Geneve
decoder and vice versa — exactly what the module doc comment and this SPEC's
design section already say ("that single omission is the whole 'lean over-WG'
claim"; no payload-length field; WireGuard replaces backbone MAC addressing).

Consequently no golden test was added here: a "golden" built from real VXLAN/
Geneve bytes would assert nothing about `encode`/`decode`, which never produce
or consume that wire format — the mandate is to assert real content against
code under test, not to freeze an unrelated protocol's bytes next to code that
doesn't speak it. The genuine, narrower fact this capture *does* establish
(24-bit VNI at a fixed offset, big-endian, in both real sibling protocols) is
recorded above as design-provenance confirmation, not as a code anchor. No
`/NOTICE` entry: this was a black-box run of the kernel's own network stack —
observed behavior only, no source or design consulted beyond the two RFCs
already cited (root `NOTICE` §0).

## Backlog / deferred

No Fable-tier piece was needed: the header is a clean-room layout from published
overlay specs and the two decision helpers are total pure functions. The genuinely
hard part of the fabric — loop-free BUM-tree reconvergence and designated-forwarder
election under partition — is intentionally **not** here; it lives in the S1b
`loopfree-reconv` / `df-elect` modules, which this codec feeds.

## Status

`gap · any · codec · reentrant` · deps: none (std only) — canonical source is
`pub const meta` in `src/root.zig`.

## Anchoring

**Anchor grade:** class A · oracle SELF

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle SELF** — round-trip and/or hand-authored fixtures only — the weakest grade.

**What the tests actually contain.** golden byte-layout KAT hand-authored from spec layouts; SPEC.md: no live-interop surface

**How it got there.** No external oracle exists for what remains. REFUTED a58d626: own 8-byte format, shares no wire shape with VXLAN/Geneve (captured)
