# bolt8

Lightning BOLT#8 encrypted transport — the `Noise_XK_secp256k1_ChaChaPoly_
SHA256` handshake (`act1`/`act2`/`act3`) plus the post-handshake
Lightning-message transport, incl. its every-500-messages key rotation.
Builds on this repo's own `noise` module (the generic Noise Protocol
Framework core).

**Status: complete.** The full three-act handshake (both sides), the wire
framing, the secp256k1 DH primitive, and the ENTIRE post-handshake
transport — including key rotation — are implemented and KAT-verified
byte-exact against the official BOLT#8 Appendix A vectors (positive AND
negative, zero skipped tests). See `SPEC.md` for the design (why the
handshake is driven over this repo's already-KAT-verified
`noise.SymmetricState` rather than `noise.HandshakeState`) and its
"TODO(fable) — done record" for the per-function verification detail.

| File | Contents |
|---|---|
| `dh.zig` | `Secp256k1DH` — BOLT#8's `ECDH(k, rk)` adapter, `KeyPair` (REAL) |
| `act.zig` | `Act1`/`Act2`/`Act3` — the fixed 50/50/66-byte handshake framing (REAL) |
| `handshake.zig` | `Initiator`/`Responder` — the `Noise_XK` act driver (REAL) |
| `transport.zig` | `Transport` — post-handshake message framing + key rotation (REAL) |
| `kat_vectors.zig` | The official BOLT#8 Appendix A test vectors, embedded |
| `kat_test.zig` | Full-handshake KAT assertions (end-to-end + all negative vectors) |

## Import

```zig
const bolt8 = @import("bolt8");
```

## API surface

**The secp256k1 DH adapter**:

```zig
const kp = try bolt8.Secp256k1DH.KeyPair.generateDeterministic(seed); // or .generate(random)
const shared = try bolt8.Secp256k1DH.dh(my_secret, remote_pub_33_bytes); // [32]u8
```

**The handshake driver**:

```zig
var initiator = bolt8.Initiator.init(my_static_keypair, responder_static_pubkey);
const act1 = try initiator.genAct1(random);
try initiator.readAct2(act2_from_wire);
const done = try initiator.genAct3();
// done.msg -> send over the wire; done.result -> bolt8.Transport.init(done.result)

var responder = bolt8.Responder.init(my_static_keypair);
try responder.readAct1(act1_from_wire);
const act2 = try responder.genAct2(random);
const result = try responder.readAct3(act3_from_wire);
```

**The post-handshake transport** (once a `HandshakeResult` is in hand):

```zig
var t = bolt8.Transport.init(handshake_result);

var out: [bolt8.transport.length_frame_len + msg.len + 16]u8 = undefined;
try t.sendMessage(msg, &out); // frames + encrypts + auto-rotates every 500 messages

const l = try t.recvLength(wire_bytes[0..bolt8.transport.length_frame_len]);
var plain: [l]u8 = undefined; // caller-sized once `l` is known
try t.recvMessage(wire_bytes[bolt8.transport.length_frame_len..][0 .. l + 16], &plain);
```

## Verify

```
zig build test-bolt8                       # Debug
zig build test-bolt8 -Doptimize=ReleaseFast # ReleaseFast
zig fmt --check modules/bolt8/
```

The official BOLT#8 Appendix A test vectors (`src/kat_vectors.zig`) are
exercised across `dh.zig`/`act.zig`/`handshake.zig`/`transport.zig`/
`kat_test.zig`'s own test blocks — see `SPEC.md`'s "Verification" section
for the full list.

Provenance: see [NOTICE](NOTICE).
