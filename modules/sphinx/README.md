# sphinx

Lightning BOLT#4 Sphinx onion routing — the mix-net packet construction
that gives Lightning HTLC payments per-hop unlinkability: a forwarding hop
learns only its immediate predecessor and successor, never the full route
or its own position in it.

**Status: complete.** The fixed 1366-byte packet codec, the BOLT#4
key-derivation primitives, the BOLT#1 `bigsize` codec, the per-hop TLV
framing, AND the three crypto cores — `deriveHopSecrets` (the shared-secret
+ blinding chain), `construct` (packet assembly, incl. filler generation),
and `process` (one hop's unwrap) — are all implemented and KAT-tested
against the official BOLT#4 test vector, including `construct` reproducing
the published 1366-byte onion packet byte-exact and a full 5-hop
construct → process round-trip. See `SPEC.md` for the full design and
threat model.

| File | Contents |
|---|---|
| `bigsize.zig` | BOLT#1's canonical variable-length integer codec (REAL) |
| `keyderive.zig` | `generateKey`/`generateCipherStream` — BOLT#4 "Key Generation" + "Pseudo Random Byte Stream" (REAL) |
| `packet.zig` | `OnionPacket` — the fixed 1366-byte wire packet, parse/serialize (REAL) |
| `hopframe.zig` | Per-hop `bigsize(length) ‖ payload ‖ hmac` framing + shift-size arithmetic (REAL) |
| `core.zig` | `deriveHopSecrets`/`construct`/`process` — the Sphinx crypto cores |
| `kat_vectors.zig` | The official BOLT#4 test vector, embedded |
| `kat_test.zig` | KAT assertions against the official vector — all live, zero skips |

## Import

```zig
const sphinx = @import("sphinx");
```

## API surface

**The wire packet** (1366 bytes: `version(1) ‖ public_key(33) ‖
hop_payloads(1300) ‖ hmac(32)`):

```zig
const pkt = try sphinx.OnionPacket.fromBytes(bytes); // rejects version != 0, invalid public_key
const bytes_out = pkt.toBytes();
```

**Key derivation** (BOLT#4 "Key Generation" / "Pseudo Random Byte
Stream"):

```zig
const rho = sphinx.generateKey(.rho, shared_secret); // .rho | .mu | .um | .pad
var stream: [1300]u8 = undefined;
sphinx.generateCipherStream(rho, &stream); // ChaCha20(rho, nonce=0) keystream
```

**BOLT#1 `bigsize`** (the per-hop payload length prefix):

```zig
var buf: [9]u8 = undefined;
const encoded = sphinx.bigsize.write(272, &buf);
const decoded = try sphinx.bigsize.read(encoded); // .{ .value = 272, .len = 3 }
```

**Per-hop TLV framing** (inside the 1300-byte `hop_payloads`):

```zig
const shift = sphinx.hopframe.shiftSize(payload.len); // 1|3 + len + 32
sphinx.hopframe.rightShift(&hop_payloads, shift);
const frame = try sphinx.hopframe.writeHopFrame(&hop_payloads, payload, next_hmac);
const parsed = try sphinx.hopframe.readHopFrame(&hop_payloads); // .payload / .hmac / .consumed
```

**The crypto cores** (`hop_payloads` entries are the raw TLV content
WITHOUT their bigsize length prefix — `construct` adds it per hop):

```zig
var secrets: [n]sphinx.HopSecret = undefined;
try sphinx.deriveHopSecrets(session_key, hop_pubkeys, &secrets);

const pkt = try sphinx.construct(session_key, hop_pubkeys, hop_payloads, associated_data);

const result = try sphinx.process(node_privkey, pkt, associated_data);
const this_hops_tlv = result.payload();
if (result.next_packet) |next| {
    // forward next.toBytes() to the next hop
} else {
    // this node is the final recipient
}
```

## Verify

```
zig build test-sphinx                       # Debug
zig build test-sphinx -Doptimize=ReleaseFast # ReleaseFast
zig fmt --check modules/sphinx/
```

The official BOLT#4 test vector (`src/kat_vectors.zig`, from
`bolt04/onion-test.json` + `04-onion-routing.md`'s "Test Vector" section)
is exercised in `src/kat_test.zig` (zero skips): the published 1366-byte
onion packet round-trips through `OnionPacket`; every published node
private key derives its published public key; `deriveHopSecrets`
reproduces all 5 published per-hop shared secrets byte-exact;
`construct` reproduces the published 1366-byte onion packet BYTE-EXACT;
`process` peels hop 0 of the published packet; a full construct → 5x
process round-trip recovers every hop's TLV payload with the final hop
flagged; and a tampered hmac / wrong node key both fail closed with
`error.IntegrityCheckFailed` (constant-time compare).

Provenance: see [NOTICE](NOTICE).
