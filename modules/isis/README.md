# isis

A pure-Zig **IS-IS (ISO/IEC 10589) PDU codec** — encode *and* decode the wire
format of the link-state routing protocol, including the **SPB (IEEE 802.1aq /
RFC 6329)** control-plane TLVs an SPB fabric runs on. It is a codec only: it
turns byte buffers into typed PDUs/TLVs and back. There is **no state machine**
here — no adjacency FSM, no LSP database, no flooding, no SPF; those consume
this module.

Status: **gap** — first increment. Models the common header, the TLV framework,
the IIH (Hello) / LSP / CSNP / PSNP PDUs, the common TLVs, and the SPB sub-TLVs.
Caveats: typed PDU bodies decode only the **6-octet system-id** (the SPB/default
case); `Lsp.decode` carries the ISO Fletcher checksum as a raw field and
validates nothing, though the checksum itself is now available — `checksum.
{compute,verify}` (ISO 8473 / RFC 905 Annex B) with the ISO 10589 §7.3.11 LSP
framing in `pdu.{computeLspChecksum, checkLspChecksum, stampLspChecksum}` and
`LspBuilder.finishStamped`; the long tail of the IANA TLV registry stays
reachable through the raw escape hatch.
See `SPEC.md` for the deliberately-deferred list.

Model after: ISO/IEC 10589 (IS-IS), RFC 1195 / 5301 / 5305 (IP/hostname/TE
TLVs), and RFC 6329 + RFC 6165 (SPB / MT-Capability). Type numbers are from the
IANA IS-IS TLV/sub-TLV code-point registries cross-checked against RFC 6329.

## What's in it

| Layer | Covers |
|-------|--------|
| `header` | The 8-byte common PDU header (discriminator `0x83`, length indicator, ID length, 5-bit PDU type, max-area-addresses) + the typed `PduType` enum (L1/L2 LAN IIH, P2P IIH, L1/L2 LSP, L1/L2 CSNP/PSNP). |
| `tlv` | The bounds-checked TLV core: zero-copy `TlvIterator` (top-level *and* sub-TLVs), the `RawTlv` escape hatch, `findFirst`/`count`, and a caller-buffer `Builder`. |
| `tlvs` | Typed views of the common TLVs — Area Addresses (#1), IS Neighbours LSP (#2), IS Neighbours IIH SNPAs (#6), LSP Entries (#9), Extended IS Reachability (#22, with sub-TLVs), Protocols Supported (#129), Dynamic Hostname (#137). |
| `pdu` | The IIH (LAN + P2P), LSP, CSNP, and PSNP bodies, each with a decoder and a `Builder` that backfills the PDU-Length field. |
| `spb` | The SPB MT-Capability (#144, in LSPs) / MT-Port-Capability (#143, in IIH) container + the **SPB Instance** (sub-TLV 1) and **SPBM Service Identifier and Unicast Address** (sub-TLV 3 — B-MAC, Base VID, per-I-SID T/R bits) sub-TLVs. |

### Modeled vs raw-only

**Modeled as typed structs:** PDU types 15/16/17/18/20/24/25/26/27; TLVs #1, #2,
#6, #9, #22, #129, #137, #143, #144; SPB sub-TLVs 1 (SPB-Inst) and 3 (SPBM-SI).

**Raw-only** (reachable verbatim through `tlv.TlvIterator` / `RawTlv`, and they
round-trip byte-exact): every other TLV code — Padding #8, Authentication #10,
IP Interface Address #132, Extended IP Reachability #135, IPv6 reachability,
MT-ISN #222, …; the SPB sub-TLVs SPB-Inst-Opaque #2, SPBV #4 (in #144) and
SPB-MCID #4 / SPB-Digest #5 / SPB-B-VID #6 (in #143). Modeling any of them later
is additive — no wire change.

## Conventions

- **System-id length = 6 octets** (MAC-sized, the SPB/default case; on the wire
  the ID-Length byte `0` denotes 6). The typed PDU bodies decode only this
  length and return `UnsupportedIdLength` otherwise; the raw TLV walk is
  id-length-independent and always works. Encode always stamps id-length 6.
- **Big-endian** for every multi-byte integer field (network byte order).
- **LSP-ID** is the 8-octet system-id(6) + pseudonode(1) + LSP-number(1); the
  **LAN-ID/DIS** is 7 octets (system-id + pseudonode); system-ids and area/NSAP
  bytes are carried as opaque byte fields — the caller interprets them (this
  module pulls in no address library).

## Untrusted-decode guarantees

`decode` runs on bytes straight off an untrusted link. It:

- allocates **nothing** on the decode path — every value is a subslice of the
  input, so a decode can never allocate more than its input;
- bounds-checks **every** TLV/sub-TLV length against the remaining buffer before
  slicing — a length that lies about the buffer is a typed error, never an
  over-read;
- terminates every walk (each TLV step advances ≥ 2 bytes) and never recurses
  unboundedly (nesting is one explicit level at a time);
- validates each body's PDU-Length field into `[fixed_len, buf.len]`, so a
  lying length cannot push the TLV region outside the buffer;
- returns typed errors (`Truncated`, `TruncatedTlv`, `BadPduLength`,
  `WrongPduType`, …) for every malformed input — never a panic.

The standing regression is a `std.testing.fuzz` target over the whole
PDU/TLV decoder plus a permanent positive-control test that a length-trusting
walk *would* over-read where the safe walk refuses.

## API sketch

```zig
const isis = @import("isis");

// Decode: dispatch on PDU type.
switch (try isis.decode(bytes)) {
    .lsp => |lsp| {
        var it = lsp.tlvIterator();               // bounds-checked TLV walk
        while (try it.next()) |t| switch (t.code) {
            isis.tlvs.code.dynamic_hostname => useName(t.value),
            isis.tlvs.code.mt_capability => {      // drill into SPB
                const cap = try isis.spb.MtCapability.decode(t.value);
                var subs = cap.subTlvIterator();
                while (try subs.next()) |s| { /* SPBM-SI etc. */ }
            },
            else => {},                             // raw escape hatch
        };
    },
    else => {},
}

// Encode: build a PDU in a caller buffer, add TLVs, finish.
var buf: [1500]u8 = undefined;
var b = try isis.pdu.LspBuilder.init(&buf, .{ .remaining_lifetime = 1200,
    .lsp_id = .{0,0,0,0,0,1,0,0}, .sequence_number = 1,
    .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 } });
try isis.tlvs.addHostname(&b.tlvs, "node-a");
const wire = b.finish();                            // PDU-Length backfilled
```

## Test

```
zig build test-isis
```

Golden P2P-IIH and SPB-carrying LSP PDUs pinned byte-for-byte (builder
reproduces them, decoder recovers every field), encode↔decode round-trips
including the raw escape hatch, per-TLV bounds-safety unit tests, and the
`std.testing.fuzz` target. Green in Debug and ReleaseFast; `zig fmt` clean.

Provenance: clean-room from the public specifications above; no third-party
IS-IS implementation or dissector (frrouting, Wireshark, tcpdump) source was
ported or studied. See `/NOTICE` (no entry required — public specs). License: MIT.
