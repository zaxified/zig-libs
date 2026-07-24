# tenantkex — design & threat model

Purpose and API: see [README.md](README.md). This document is the auditor
altitude — the message flow, exactly what is bound and where, the
key-orientation derivation, the failure semantics, the aeadframe handoff, the
security model given the WG tunnel underneath, and what is deferred. Meta tags
live in `src/root.zig`; this file does not restate them.

## 1. Model

`Noise_IK_25519_ChaChaPoly_SHA256`, driven over this repo's own `noise` module
(`noise.DefaultSuite.HandshakeState`). tenantkex is a **composition** module: it
reimplements no crypto — DH, AEAD, HKDF, the transcript hash and `split()` all
run inside `noise`, which is itself byte-exact against the official noise-c IK
vectors. tenantkex adds exactly three things: (a) the fixed-format prologue that
binds tenant/PE identity, (b) a two-step state machine per role, and (c) the
role-resolved `send_key`/`recv_key` mapping out of `split()`.

The reference for using IK this way is WireGuard, which likewise runs a fixed
`Noise_IK*` instantiation between provisioned peers whose static keys are known
in advance.

## 2. Message flow

IK pattern (spec §9), pre-message `<- s` (responder static known to initiator):

```
msg1:  -> e, es, s, ss   [+ optional payload]
msg2:  <- e, ee, se      [+ optional payload]
```

Wire sizes (ChaCha20-Poly1305, 16-byte tags):

| message | tokens on wire | bytes |
|---------|----------------|-------|
| msg1 | `e`(32) + encrypted `s`(32+16) + payload(+16) | `96 + payload` |
| msg2 | `e`(32) + payload(+16) | `48 + payload` |

`message1Len`/`message2Len` expose these. The initiator drives
`writeMessage1` → `readMessage2`; the responder `readMessage1` →
`writeMessage2`. A per-role `state` enum rejects out-of-order/duplicate calls
with `error.WrongState` before touching `noise`.

## 3. What is bound, and where

Binding goes in the **prologue**, not the payload. Rationale: the prologue is
mixed into the transcript hash `h` at `Initialize` time (`MixHash(prologue)`),
*before* any message. `h` is then the AEAD associated-data for every
`EncryptAndHash`/`DecryptAndHash`. In IK's `msg1` the very first encrypted token
is the initiator's static key `s` (encrypted after the `es` DH). So if the two
sides' prologues differ, `h` diverges and the responder's `DecryptAndHash` of
that `s` token fails its Poly1305 tag — the handshake dies on `msg1`, before any
key is derived. Putting the binding in a *payload* would instead let the
handshake half-complete and only fail later (or not at all if a side ignores the
payload); the prologue makes the binding load-bearing and unavoidable.

Prologue layout (fixed width, all integers big-endian):

```
  prologue_label ("tenantkex/v1 Noise_IK_25519_ChaChaPoly_SHA256")
  ‖ I-SID          (u24, 3 bytes)   -- the tenant, matches l2encap/l2forward
  ‖ initiator_pe   (u32, 4 bytes)   -- fabric PE ids, pin the endpoint pair
  ‖ responder_pe   (u32, 4 bytes)
```

The label is a versioned domain separator: any future wire change bumps it and
becomes a different, non-interoperable transcript. Binding the PE pair in
addition to the I-SID pins a session to a specific directed edge of the fabric,
so a msg1 minted for one PE pair cannot be replayed into a different pair even
at the same I-SID.

## 4. Key-orientation derivation

`SymmetricState.split()` (spec §5.2) returns `[2]CipherState`: index `0` =
initiator→responder, index `1` = responder→initiator (both ends compute the
identical pair). tenantkex resolves this per role once, so callers never see an
index:

```
initiator:  send_key = pair[0].k   recv_key = pair[1].k
responder:  send_key = pair[1].k   recv_key = pair[0].k
```

Invariant (asserted by the mutual-handshake test):
`initiator.send_key == responder.recv_key` and
`initiator.recv_key == responder.send_key`. `transcript_hash` is
`getHandshakeHash()` (the final `h`); `noise`'s `wipe()` zeroes the chaining key
and handshake cipher key after `split()` but leaves `h` intact, so it stays
available.

## 5. Security model (given the WG tunnel underneath)

* **Mutual authentication.** IK authenticates the responder to the initiator
  (the initiator encrypts to a static key only the real responder holds) and the
  initiator to the responder (the responder learns and DH-mixes the initiator's
  static in `msg1`). A party holding the wrong counterpart static key cannot
  complete the handshake (`error.DecryptionFailed`) — see the wrong-key test.
* **Tenant isolation.** The prologue binding (§3) makes each completed session
  provably scoped to one `(I-SID, PE-pair)`. This is the whole point: many
  tenants share one WG tunnel, and this layer keeps them cryptographically
  separate from *each other*, which the single outer tunnel key cannot.
* **Forward secrecy** of the session keys follows from the ephemeral DHs
  (`ee`, plus `es`/`se`), per Noise IK.
* **Identity hiding.** IK reveals less than a cleartext handshake but is weaker
  than XX (the initiator commits to the responder's identity, and its own static
  is sent in `msg1` encrypted only to the responder). This is **not a concern
  here**: the entire handshake already travels inside the PEs' authenticated,
  encrypted WireGuard tunnel, so no off-path observer sees any of it, and the PE
  pair is already mutually known infrastructure. We therefore do not add the
  extra round trips XX would cost.
* **Replay / freshness.** Session-establishment replay of a whole `msg1` is
  bounded by the fresh ephemerals and by the WG tunnel's own replay protection;
  in-session record replay is `aeadframe`'s job (its sliding window), not this
  module's.
* **No partial keys.** Any failure path (tamper, wrong static, prologue
  mismatch, truncation) returns a typed error from `noise`'s `readMessage`
  *before* `split()`; keys are only ever returned on the fully-authenticated
  completion path.

### Positive control

A permanent test (`positive control: WITHOUT the I-SID ...`) drives the raw
`noise` IK handshake with a prologue reduced to just the label — no I-SID, no PE
ids — and shows two conceptually-different tenants then complete a handshake.
This proves the isolation comes from the `FabricContext` binding in §3 and
nothing else; were that test to fail, the isolation guarantee would be resting
on something unaudited.

### KAT anchoring

tenantkex adds only the prologue to `noise` IK, so the KAT uses `noise` as the
oracle: raw `noise.HandshakeState` driven with the same injected ephemerals and
tenantkex's computed prologue produces byte-identical `msg1`/`msg2` and
identical `split()` keys to `tenantkex.Initiator`/`Responder`. Since `noise` is
itself byte-exact against the official noise-c IK vectors, this pins both the
prologue construction and the split→key mapping without duplicating vectors. (A
standalone external vector is impossible: the published IK vectors use a
different prologue, so their bytes do not apply to tenantkex's transcript.)

## 6. Deferred

* **XX fallback** — when the responder's static key is *not* pre-provisioned.
  Would add a 3-message pattern and in-band responder-static transmission.
* **PSK modes (IKpsk2)** — an additional pre-shared secret mixed in as a
  quantum-resistance hedge; `noise` already implements the `psk` token.
* **Rekey / rehandshake scheduling** — in-session rekey is `aeadframe`'s epoch
  bump; a fresh handshake is simply a new tenantkex session. No scheduler here.
* **Retransmission / timeout** of handshake messages — owned by the caller's
  transport (the WG-backed channel), not this module.
