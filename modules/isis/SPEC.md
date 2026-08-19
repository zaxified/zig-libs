# isis — spec

Design + threat notes for auditors. Usage, API, and the module purpose: see
[README.md](README.md) and the `src/*.zig` doc comments. Attribution/provenance:
see `/NOTICE` — none required (clean-room from public specs: ISO/IEC 10589,
RFC 1195/5301/5305, RFC 6329/6165; a public spec is not a copyrightable work,
and no third-party IS-IS source or dissector was ported or studied).

## Scope

A **pure wire codec** for IS-IS PDUs and TLVs — the control-plane byte layer an
SPB (IEEE 802.1aq) fabric runs on. This module encodes and
decodes; it holds no state. The adjacency FSM, LSP database, flooding/SRM-SSN,
SPF, and the SPB tree computation are separate consumer modules built on top.

## Wire format

### Common header (ISO 10589 §9.1) — 8 octets

| Off | Field | Notes |
|-----|-------|-------|
| 0 | Intradomain Routing Protocol Discriminator | constant `0x83`; rejected otherwise |
| 1 | Length Indicator | length of the **fixed** header (common + type-specific): 20 (P2P IIH), 27 (LAN IIH / LSP), 33 (CSNP), 17 (PSNP). Not the total PDU length. |
| 2 | Version / Protocol ID Extension | constant `1` |
| 3 | ID Length | `0 ⇒ 6`, `255 ⇒ 0`, else literal. Normalized to `id_length` |
| 4 | R R R + PDU Type (low 5 bits) | reserved bits rejected if set |
| 5 | Version | constant `1` |
| 6 | Reserved | carried verbatim (soft field) |
| 7 | Maximum Area Addresses | `0 ⇒ 3` |

`header.decode` validates only these 8 octets, so a caller may decode a bare
common header. The upper bound on the Length Indicator (the type-specific header
must actually be present) is the **body** decoder's concern — each body verifies
`buf.len >= fixed_len` and returns `TruncatedBody` otherwise.

### PDU bodies

- **IIH LAN (15/16):** circuit-type, 6-octet source-id, holding-time, PDU-Length,
  7-bit priority, 7-octet LAN-ID (DIS). Fixed header 27.
- **IIH P2P (17):** circuit-type, source-id, holding-time, PDU-Length,
  local-circuit-id. Fixed header 20.
- **LSP (18/20):** PDU-Length, remaining-lifetime, 8-octet LSP-ID, 32-bit
  sequence-number, 16-bit checksum, flags octet (P / ATT×4 / OL / IS-Type).
  Fixed header 27.
- **CSNP (24/25):** PDU-Length, 7-octet source-id, start/end LSP-ID range.
  Fixed header 33.
- **PSNP (26/27):** PDU-Length, source-id. Fixed header 17.

Each body's **PDU Length** field is validated into `[fixed_len, buf.len]`; the
TLV region is exactly `buf[fixed_len .. pdu_length]`.

### TLVs

`code(1) length(1) value(length)`, walked by `tlv.TlvIterator`. Sub-TLVs are the
same shape nested inside a value (Extended IS Reachability #22; the SPB
MT-Capability #144 / MT-Port-Cap #143 containers). Modeled codes and their
sources:

| Code | Name | Source |
|------|------|--------|
| 1 | Area Addresses | ISO 10589 |
| 2 | IS Neighbours (LSP, old-style) | ISO 10589 §9.8 |
| 6 | IS Neighbours (IIH SNPAs) | ISO 10589 §9.5/9.7 |
| 9 | LSP Entries (for CSNP/PSNP) | ISO 10589 §9.10 |
| 22 | Extended IS Reachability (+ sub-TLVs) | RFC 5305 |
| 129 | Protocols Supported | RFC 1195 |
| 137 | Dynamic Hostname | RFC 5301 |
| 143 | MT-Port-Capability (SPB, IIH) | RFC 6165 / 6329 |
| 144 | MT-Capability (SPB, LSP) | RFC 6329 |

## SPB TLV layout + provenance of the numbers

All SPB numbers are from **RFC 6329** (IANA registrations), cross-checked
against the IANA IS-IS TLV and sub-TLV code-point registries:

- Container **MT-Capability = TLV 144** (in LSPs), **MT-Port-Capability = TLV 143**
  (in IIH). Both open with a 2-octet preamble: `O` (overload) bit, 3 reserved
  bits, 12-bit MT-ID — then a sub-TLV stream.
- **SPB Instance = sub-TLV 1** (of 144): 8-octet CIST Root Identifier, 4-octet
  CIST External Root Path Cost, 2-octet Bridge Priority, a 4-octet word
  `R(11) | V(1) | SPSourceID(20)`, 1-octet Num-of-Trees, then N × 8-octet
  ECT-VID tuples `U|M|A|Res(5) · ECT-ALGORITHM(32) · BaseVID(12)|SPVID(12)`.
- **SPBM Service Identifier and Unicast Address ("SPBM-SI") = sub-TLV 3**
  (of 144): 6-octet B-MAC, 2-octet `Res(4) | Base-VID(12)`, then N × 4-octet
  I-SID entries `T|R|Res(6) · I-SID(24)`. T = transmit-allowed, R =
  receive-allowed.

The bit orderings (V bit at position 20 of the SPB-Inst word; Base-VID in the
**low** 12 bits of the SPBM-SI 2-octet field; T/R as the two MSBs of each I-SID
entry) were taken from the verbatim RFC 6329 figures and are pinned in the LSP
golden. No number here is a guess; where a sub-TLV is not modeled it is named in
the raw-only list, not invented.

## Threat model / untrusted decode

`decode` consumes bytes off an untrusted link (a hostile or buggy peer, or an
attacker who can inject frames). The central hazard of a TLV codec is an
**attacker-controlled length**. Defenses:

- **One length-check implementation.** Top-level TLVs and sub-TLVs both use
  `tlv.TlvIterator`; there is a single `value_start + len > buf.len` guard to
  audit. `len` is a `u8` (≤ 255) and the sum is `usize`, so it cannot wrap.
- **Zero allocation on decode.** Every `value`/`sub_tlvs`/`tlv_bytes` is a
  subslice of the input; a decode cannot allocate more than its input, by
  construction. The fuzz target asserts each yielded value lies strictly within
  the input `ptr..ptr+len`.
- **Guaranteed termination.** Each TLV step advances `pos` by ≥ 2. The typed
  record iterators (SNPA, IS-reach, LSP-entries, ECT-VID, I-SID) advance by
  their fixed record size and reject a partial trailing record. No walk can
  loop.
- **Bounded nesting.** The walker never recurses on itself; the typed decoders
  descend exactly one sub-TLV level, so a crafted PDU cannot induce unbounded
  recursion or stack growth.
- **Body length lies caught.** A PDU-Length below the fixed header or beyond the
  buffer is `BadPduLength`; a Length-Indicator below 8 is `BadLengthIndicator`;
  an SPB Num-of-Trees or I-SID run exceeding the sub-TLV value is `BadLength`.
- **No reserved-field smuggling in the header:** the 3 reserved PDU-type bits
  are rejected, not masked.

**Not an authentication boundary.** The Authentication TLV (#10) and IS-IS
crypto-auth (RFC 5304/5310) are **not** implemented — this codec neither
verifies nor produces an authentication TLV; it carries #10 as raw bytes. SPB
integrity (RFC 6329 digest exchange) is likewise out of scope. A consumer that
needs authenticated IS-IS must layer it above this codec.

## Verification

Offline only — pure codec, no live-interop surface in this environment.
`zig build test-isis`:

- **Goldens** (`goldens.zig`): a P2P IIH and an SPB-carrying L1 LSP, each
  hand-assembled field-by-field per ISO 10589 / RFC 6329 (**no live capture was
  available** — stated honestly) and pinned byte-for-byte. Three directions: the
  builders reproduce the golden bytes, the decoders recover every field, and
  `encode(decode(golden)) == golden`. The Length-Indicator/PDU-Length constants
  (20 / 27 / 37 / 60) are an independent cross-check on the hand assembly.
- **Round-trip:** encode↔decode over empty TLV sets, max-length (255) and
  zero-length TLVs, repeated same-code TLVs, and the raw escape hatch (an
  unmodeled type re-emits verbatim).
- **Bounds-safety units:** truncated headers, overrunning TLV lengths, lying
  body PDU-Length, oversize builder values, partial trailing records in every
  typed iterator, and the SPB sub-length lies.
- **Positive control (permanent):** `tlv.zig` proves a length-trusting walk
  *would* over-read (`2 + declared_len > buf.len`) where the safe walk returns
  `TruncatedTlv` — so the test goes red the moment the guard is removed.
- **Fuzz:** a `std.testing.fuzz` target driving arbitrary bytes through the
  dispatch decoder + raw and sub-TLV walks, asserting never-panic, walk
  termination, and value-within-input.

Green in Debug and `-Doptimize=ReleaseFast`; `zig fmt --check` clean;
`zig build check-catalog` exit 0.

## Deliberately deferred (out of scope by design, not oversight)

- **All protocol state**: adjacency FSM (up/init/down), the LSP database,
  flooding (SRM/SSN flags, CSNP/PSNP-driven synchronization *logic* — the PDUs
  are modeled, the exchange algorithm is not), SPF/route computation, and the
  SPB shortest-path-tree / ECT computation. This module supplies the bytes those
  consumers exchange.
- ~~**ISO Fletcher checksum** compute/verify~~ — **now implemented**, additively:
  `checksum.{compute,verify}` (ISO 8473 Annex C / RFC 905 Annex B) plus the LSP
  framing in `pdu.{lspChecksumRegion, computeLspChecksum, checkLspChecksum,
  stampLspChecksum}` and `LspBuilder.finishStamped`, per ISO 10589 §7.3.11 ("The
  checksum shall be computed over all fields in the LSP which appear after the
  Remaining Lifetime field"). `Lsp.decode` is unchanged — it still carries the
  raw 16-bit field and validates nothing, so the wire behaviour and the
  zero-allocation decode contract are untouched. A zero field means "not
  computed" (`ChecksumStatus.not_present`); the receive **policy** built on that
  — ISO §7.3.14.2's discard — belongs to the update process (`isis-lsdb`), not
  here.
- **Non-default ID lengths** in the typed bodies (only 6 is wired; the raw TLV
  walk is id-length-independent).
- **Authentication TLV (#10)** and IS-IS crypto-auth (RFC 5304/5310); SPB digest
  (RFC 6329) integrity.
- **Multi-Topology topologies** beyond carrying the MT-ID — MT-ISN (#222), the
  MT-aware reachability set.
- **The long tail of the IANA TLV registry** (IP reachability #128/#130/#135,
  IP Interface Address #132, TE sub-TLVs, segment-routing, etc.) and the
  un-modeled SPB sub-TLVs (SPB-Inst-Opaque, SPBV, SPB-MCID, SPB-Digest,
  SPB-B-VID) — all reachable and byte-exact through the raw escape hatch;
  modeling any is additive.

## Status

`gap · any · codec · reentrant` · deps: none (std only) — canonical source is
`pub const meta` in `src/root.zig`.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** Wireshark sharkd validated 5 PDU bodies + TLVs incl. L2 CSNP/PSNP (goldens.zig); long-tail raw-TLV escape hatch stays self-tested

**How it got there.** The anchoring work landed. CLOSED 2026-08-05: L2 CSNP (25) and L2 PSNP (27) type codes driven through this module's own CsnpBuilder/PsnpBuilder and confirmed by sharkd (goldens 8-9, goldens.zig; mutation-tested). Remaining gap: the long-tail raw-TLV/sub-TLV escape hatch (Auth #10, IP-reach, unmodeled SPB sub-TLVs, non-default id-lengths) stays self-tested only — by design unmodeled, so there is no typed content for Wireshark to validate
