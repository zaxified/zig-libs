# tenantkex

Per-tenant key exchange for an encrypted L2VPN fabric: two provider edges (PEs) that
already share the encrypted WireGuard backbone run, **per tenant**, an
independent authenticated `Noise_IK` handshake (via the `noise` module) and
derive the two directional 32-byte transport keys that feed a pair of
`aeadframe` channels. Binding the tenant's I-SID (plus the two PE ids) into the
Noise **prologue** scopes a completed session to exactly one tenant — a
transcript for tenant A cannot be accepted as tenant B, which is the
cryptographic tenant-isolation guarantee compliance needs.

This is a thin, allocation-light **driver over `noise`** — it reimplements no
cryptography. The caller carries the two handshake messages over the WG tunnel;
this module produces `{ send_key, recv_key, transcript_hash }`.

Meta tags (platform/role/concurrency/model_after/deps) live in
`src/root.zig`'s `pub const meta`; design/threat detail lives in
[SPEC.md](SPEC.md). Provenance: clean-room composition — the crypto is entirely
in `noise` (see its NOTICE); no third-party source is ported here.

## Model — `Noise_IK_25519_ChaChaPoly_SHA256`

IK = the **initiator already knows the responder's static public key** (the
orchestrator provisions PE static keys on the fabric — realistic and the reason
IK, not XX, is the default). Two-message flow, then both sides `split()`:

```
initiator  --msg1( e, es, s, ss )-->  responder
initiator  <--msg2( e, ee, se )-----  responder
both: split() -> two directional transport keys
```

`msg1` carries the initiator's ephemeral, its static key (encrypted to the
responder), and an optional payload; `msg2` carries the responder's ephemeral
and an optional payload. After `msg2` both ends hold the same key pair and pick
their sending direction by role.

## Key orientation contract (the footgun — pinned by a permanent test)

Noise `split()` returns `pair[0]` = initiator→responder and `pair[1]` =
responder→initiator. Therefore:

| role | `send_key` | `recv_key` |
|------|-----------|-----------|
| initiator | `pair[0].k` | `pair[1].k` |
| responder | `pair[1].k` | `pair[0].k` |

so `initiator.send_key == responder.recv_key` and
`initiator.recv_key == responder.send_key`. This module returns each side's
`send_key`/`recv_key` already resolved for that role — the caller never touches
a split index.

## I-SID prologue binding

The prologue is `prologue_label ‖ I-SID(u24, BE) ‖ initiator_pe(u32, BE) ‖
responder_pe(u32, BE)` (a fixed-width `FabricContext`). Both PEs must agree on
every field: the prologue feeds Noise's transcript hash `h`, and `h` is the AEAD
associated-data for `msg1`'s encrypted `s` token — so a mismatched I-SID (or PE
id) makes the responder's `readMessage1` fail its authentication tag and yield
**no keys**. That failure IS the tenant-isolation proof.

## aeadframe handoff

The two 32-byte keys are plain ChaCha20-Poly1305 / AES-256-GCM keys — exactly
what `aeadframe`'s `Sealer`/`Opener` take. Wire them per direction, at epoch 0:

```zig
var s = af.ChaChaChannel.Sealer.init(keys.send_key, 0); // this PE seals
var o = af.ChaChaChannel.Opener.init(keys.recv_key, 0); // this PE opens
```

`transcript_hash` is Noise's channel-binding value: a stable 32-byte session id,
non-secret, usable e.g. as the `aeadframe` `aad` or a log correlation id.
(`tenantkex` does not depend on `aeadframe` — the handoff is by raw `[32]u8`.)

## Usage

```zig
const tk = @import("tenantkex");

const ctx = tk.FabricContext{ .isid = tenant_isid, .initiator_pe = a, .responder_pe = b };

// Initiator side (knows the responder's static public key out of band):
var ini: tk.Initiator = undefined;
ini.init(&my_static_kp, responder_static_pub, ctx);  // in place, key by pointer
var m1: [tk.message1Len(0)]u8 = undefined;
const n1 = try ini.writeMessage1(rng, "", &m1);      // send m1[0..n1]
// ... receive m2 ...
var keys: tk.SessionKeys = undefined;                // filled on success only
const n = try ini.readMessage2(m2, &payload_buf, &keys); // payload length

// Responder side:
// ... knows the initiator PE's provisioned static public key, and accepts no other:
var rsp: tk.Responder = undefined;
rsp.init(&my_static_kp, initiator_static_pub, ctx);
_ = try rsp.readMessage1(m1, &payload_buf);
var m2: [tk.message2Len(0)]u8 = undefined;
var rkeys: tk.SessionKeys = undefined;
const n2 = try rsp.writeMessage2(rng, "", &m2, &rkeys); // send m2[0..n2]
```

`rng` must be a cryptographically secure `std.Random` in production (Noise draws
the ephemeral from it). `initEphemeral` injects a fixed ephemeral for KATs only.

## Context — this rides an authenticated WG tunnel

The handshake and all resulting records travel inside the PEs' existing
WireGuard tunnel, which already authenticates and encrypts the link. tenantkex
adds a *second, per-tenant* key so tenants are isolated from **each other** even
though they share that one tunnel — defence the outer WG layer cannot provide.
Because the outer tunnel already hides identities from any off-path observer,
IK's weaker identity-hiding (vs XX) is not a concern here (see SPEC.md §5).

## PSK mode (opt-in)

`Initiator.initPsk` / `Responder.initPsk` (and `initPskEphemeral`) run
`Noise_IKpsk2` with a 32-byte pre-shared secret (WireGuard-style hedge). Both
sides must use it with the same PSK; the plain IK `init` stays the default. A
wrong PSK fails the initiator's `readMessage2` with `DecryptionFailed`; a PSK on
one side only fails the responder's `readMessage1`. `wipe` destroys the module's
copy of the PSK.

## XX mode (opt-in): the responder's key is not provisioned

`XxInitiator` / `XxResponder` run a three-message `Noise_XX_25519_ChaChaPoly_SHA256`
under their own prologue label (`prologue_label_xx`, same fabric fields):

```zig
var ini: tenantkex.XxInitiator = undefined;
ini.init(&my_static, ctx); // no responder key
const n1 = try ini.writeMessage1(rng, "", &m1); // -> e (payload in CLEAR)
// responder: rsp.init(&its_static, provisioned_initiator_key, ctx);
//            rsp.readMessage1 -> rsp.writeMessage2 (<- e, ee, s, es)
var responder_key: tenantkex.PublicKey = undefined;
_ = try ini.readMessage2(m2, &pl, &responder_key);
// CHECK responder_key against your trust policy here; on refusal ini.wipe().
const n3 = try ini.writeMessage3(rng, "", &m3, &keys); // -> s, se; keys
// responder: rsp.readMessage3(m3, &pl, &keys) -- UnknownInitiator unless the
//            initiator key is the provisioned one.
```

Lengths: `xxMessage1Len` (32 + payload), `xxMessage2Len` (96 + payload),
`xxMessage3Len` (64 + payload). The mode is the caller's explicit choice: an IK
`Initiator`/`Responder` never switches to XX, and IK and XX messages are refused
across modes. It is not Noise Pipes' `XXfallback` role switch (see SPEC.md §6).

## Deferred

Noise Pipes' `XXfallback` (needs `noise`'s `fallback` modifier), rekey/rehandshake
scheduling (aeadframe's epoch handles in-session rekey; a fresh handshake is a
new session), handshake-message retransmission/timeout (the transport owns it).

## Verify

```
zig build test-tenantkex                       # Debug
zig build test-tenantkex -Doptimize=ReleaseFast
```
