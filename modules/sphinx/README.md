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
| `core.zig` | `deriveHopSecrets`/`construct`/`process` — the Sphinx crypto cores; `sharedSecret` — a hop's own ECDH step |
| `failure.zig` | BOLT#4 "Returning Errors": `create`/`forward`/`unwrap` the return-path failure packet (REAL) |
| `blinded.zig` | BOLT#4 "Route Blinding": `createPath` / `unblind` (blinded node ids, `encrypted_recipient_data`, path keys) |
| `burn.zig` | The dead-stack burn run around `generateKey` / `generateCipherStream` (`construct`/`process` carry their own in `core.zig`) |
| `kat_vectors.zig` | The official BOLT#4 test vector, embedded |
| `failure_vectors.zig` | The BOLT#4 "Returning Errors" vectors, embedded |
| `kat_test.zig` | KAT assertions against the official vector — all live, zero skips |
| `fuzz_test.zig`, `stackprobe_test.zig`, `stackprobe2_test.zig`, `stackprobe3_test.zig`, `ctgrind_harness.zig` | Fuzz driver plumbing, dead-stack probes and the constant-time harness (verification only) |

**Deps:** `k256` (secp256k1 point and scalar arithmetic); the rest is `std.crypto`.

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
var rho: [32]u8 = undefined;
sphinx.generateKey(&rho, .rho, &shared_secret); // .rho | .mu | .um | .ammag | .pad
var stream: [1300]u8 = undefined;
sphinx.generateCipherStream(&rho, &stream); // ChaCha20(rho, nonce=0) keystream
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
try sphinx.deriveHopSecrets(&session_key, hop_pubkeys, &secrets);

const pkt = try sphinx.construct(&session_key, hop_pubkeys, hop_payloads, associated_data);

const result = try sphinx.process(&node_privkey, pkt, associated_data);
const this_hops_tlv = result.payload();
if (result.next_packet) |next| {
    // forward next.toBytes() to the next hop
} else {
    // this node is the final recipient
}

// Replay protection (BOLT#4): `result.replay_tag` is SHA256(shared secret).
// Keep a log of tags yourself, or let `processWithHook` ask your log after
// the HMAC check (`hook.check(ctx, &tag)` returns false to refuse; the call
// then returns `error.Replayed`). The module stores nothing.
const r2 = try sphinx.processWithHook(&node_privkey, pkt, associated_data, .{ .ctx = &log, .check = myCheck });
```

**Returning errors** (BOLT#4 "Returning Errors", classic failure packets; `shared_secret` is the
hop's secret: `sharedSecret(&ss, &node_privkey, &pkt.public_key)` on a relay, `deriveHopSecrets` on
the sender):

```zig
// the erring node: hmac ++ failure_len ++ failuremsg ++ pad, authenticated and obfuscated
var buf: [sphinx.failure.max_packet_len]u8 = undefined;
var p = try sphinx.failure.create(&buf, &ss, failuremsg);
// every relay on the way back
p = sphinx.failure.forward(p, &my_ss);
// the origin: one shared secret per hop, first to last; the packet is decrypted in place
const src = try sphinx.failure.unwrap(p, route_secrets); // error.SourceUnidentified if no hop verifies
const failure = try sphinx.failure.parseFailure(src.data); // src.hop = index of the failing hop
```

`attribution_data` is not implemented.

Route blinding (BOLT#4; the TLV payloads are the caller's bytes):

```zig
var hops: [2]sphinx.blinded.BlindedHop = .{ .{ .blinded_node_id = undefined, .encrypted_data = &enc0 }, .{ .blinded_node_id = undefined, .encrypted_data = &enc1 } };
const first_path_key = try sphinx.blinded.createPath(&session_key, &node_ids, &payloads, &hops); // enc_i = payload_i.len + 16
// at node i:
var u: sphinx.blinded.Unblinded = undefined;
try sphinx.blinded.unblind(&node_privkey, &path_key, encrypted, plain_buf, &u); // u.blinded_privkey peels the onion, u.next_path_key goes on
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
