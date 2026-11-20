# bolt8

Lightning BOLT#8 encrypted transport — the `Noise_XK_secp256k1_ChaChaPoly_
SHA256` handshake (`act1`/`act2`/`act3`) plus the post-handshake
Lightning-message transport, incl. its every-500-messages key rotation.
Builds on this repo's own `noise` module (the generic Noise Protocol
Framework core).

The full three-act handshake (both sides), the wire framing, the secp256k1 DH primitive and the whole
post-handshake transport, including key rotation, are checked byte-exact against the official BOLT#8 Appendix A
vectors (positive and negative) and interop-tested against lnd's `brontide`. See `SPEC.md` for the design (why
the handshake is driven over `noise.SymmetricState` rather than `noise.HandshakeState`) and the verification
detail. Dependencies: `noise` (the generic Noise core; its re-exported ChaCha20-Poly1305 is the AEAD) and `k256`
(secp256k1).

| File | Contents |
|---|---|
| `dh.zig` | `Secp256k1DH` — BOLT#8's `ECDH(k, rk)` adapter, `KeyPair` |
| `act.zig` | `Act1`/`Act2`/`Act3` — the fixed 50/50/66-byte handshake framing |
| `handshake.zig` | `Initiator`/`Responder` — the `Noise_XK` act driver |
| `transport.zig` | `Transport` — post-handshake message framing + key rotation |
| `kat_vectors.zig` | The official BOLT#8 Appendix A test vectors, embedded |
| `kat_test.zig` | Full-handshake KAT assertions (end-to-end + all negative vectors) |

## Import

```zig
const bolt8 = @import("bolt8");
```

## API surface

**The secp256k1 DH adapter**:

```zig
var kp: bolt8.Secp256k1DH.KeyPair = undefined; // secrets by pointer, results by `out`
try bolt8.Secp256k1DH.KeyPair.generateDeterministicInto(&kp, &seed); // or .generate(&kp, random)
const shared = try bolt8.Secp256k1DH.dh(&my_secret, remote_pub_33_bytes); // [32]u8
```

**The handshake driver**:

```zig
// `Ephemeral` is a tagged union, not a bare `std.Random`: the Act One/Two
// ephemeral IS the per-session secret, so which kind of generator produced it
// has to be written out at the call site. `.csprng` is the production arm and
// is an assertion you make (std 0.16 removed `std.crypto.random`, so this
// module has no RNG of its own and cannot check it); `.seeded_for_test` is the
// other arm, and choosing it in production costs you initiator forward secrecy.
var csprng = std.Random.DefaultCsprng.init(seed_from_getrandom);
const entropy: bolt8.handshake.Ephemeral = .{ .csprng = csprng.random() };

var initiator: bolt8.Initiator = undefined;
bolt8.Initiator.init(&initiator, &my_static_keypair, responder_static_pubkey);
const act1 = try initiator.genAct1(entropy);
try initiator.readAct2(act2_from_wire);
var done: bolt8.HandshakeResult = undefined; // transport keys: an out-parameter, see SPEC
const act3 = try initiator.genAct3(&done);
// act3 -> send over the wire; done -> bolt8.Transport.init(&t, &done)

var responder: bolt8.Responder = undefined;
bolt8.Responder.init(&responder, &my_static_keypair);
try responder.readAct1(act1_from_wire);
const act2 = try responder.genAct2(entropy);
var result: bolt8.HandshakeResult = undefined;
try responder.readAct3(act3_from_wire, &result);
// result.remote_static is the PEER's static public key (in Lightning, its
// node id) -- the one output of the handshake's authentication step. Check
// it against whatever identity you expected to reach before trusting the
// connection; readAct3 only proves the peer knows the corresponding
// private key, not that it is who you meant to dial.
```

Each `Initiator`/`Responder` drives **one** handshake, in order. A second
`genAct1` (or any act out of sequence) is `error.WrongState`, never a silent
reuse of the previous ephemeral share — build a fresh one to retry. The
ephemeral itself is always drawn inside `genAct1`/`genAct2`; there is no way to
pin it from production code (the Appendix A vectors reach the
`genAct1WithEphemeral`/`genAct2WithEphemeral` hooks, which are declared `void`
outside a test build, so a call does not compile).

A failed act marks the object `.failed`; every later act on it is `error.WrongState`.
`HandshakeResult.wipe()` zeroes `sk`/`rk`/`ck`: call it once `Transport.init`
has copied them. `deinit()` on `Initiator`/`Responder`/`Transport`/`KeyPair` zeroes the
key material each owns.

**The post-handshake transport** (once a `HandshakeResult` is in hand):

```zig
var t: bolt8.Transport = undefined;
bolt8.Transport.init(&t, &handshake_result);

var out: [bolt8.transport.length_frame_len + msg.len + 16]u8 = undefined;
try t.sendMessage(msg, &out); // frames + encrypts + auto-rotates every 500 messages

const l = try t.recvLength(wire_bytes[0..bolt8.transport.length_frame_len]);
var buf: [bolt8.transport.max_message_len]u8 = undefined; // caller-owned upper bound
const plain = buf[0..l]; // `l` is runtime, so this must be a SLICE, not an array length
try t.recvMessage(wire_bytes[bolt8.transport.length_frame_len..][0 .. l + 16], plain);
```

## Limits

- **No I/O and no deadline.** The module is sans-io: the caller reads exactly the act or frame length off the
  wire. `Responder.readAct1` spends a secp256k1 multiply before it can check the MAC, so the caller's read loop
  needs a handshake deadline (lnd's `brontide` uses 5 s).
- **`recvLength` and `recvMessage` must alternate.** If the transport can fail between the header and the body,
  `rx` is desynced for good (every later frame is `error.DecryptionFailed`): rebuild with a fresh handshake.
- **A message is at most `transport.max_message_len` (65535) bytes**; `sendMessage` refuses more
  (`error.MessageTooLong`) and wants an `out` of exactly `length_frame_len + m.len + 16` bytes.

## Not provided

A socket or connection wrapper, a built-in handshake deadline, and anything above the Lightning-message byte
boundary (message dispatch, `init`/`ping`/gossip) are left to the caller; see `SPEC.md` *What is deliberately not
done*. The one open performance item is in *Backlog / deferred*.

## Verify

```
scripts/modtest bolt8
```

The official BOLT#8 Appendix A test vectors (`src/kat_vectors.zig`) are
exercised across `dh.zig`/`act.zig`/`handshake.zig`/`transport.zig`/
`kat_test.zig`'s own test blocks — see `SPEC.md`'s "Verification" section
for the full list.

Provenance: see [NOTICE](NOTICE).
