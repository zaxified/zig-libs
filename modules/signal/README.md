# signal

The Signal Protocol's core cryptographic building blocks, on `std.crypto`.
Planned as a two-part arc:

- **Part 1 (THIS module, as scaffolded): X3DH** — Extended Triple
  Diffie-Hellman, the asynchronous initial key-agreement
  (signal.org/docs/specifications/x3dh) — plus **XEdDSA**
  (signal.org/docs/specifications/xeddsa), the Montgomery-keypair
  signature scheme X3DH uses to sign a signed prekey.
- **Part 2 (NOT in this module): Double Ratchet** — the per-message
  forward-secret/post-compromise-secure ratchet
  (signal.org/docs/specifications/doubleratchet), seeded with X3DH's `SK`
  as its initial root key. See "Part 2 boundary" below.

**Status: Part 1 COMPLETE.** X3DH's DH+HKDF agreement, both wire codecs
(`PreKeyBundle`, `InitialMessage`), and XEdDSA (`xeddsa.sign`/
`xeddsa.verify`, including `xeddsa.edwardsFromMontgomery` — the
Montgomery->Edwards sign-0 point recovery std does not provide) are real
and tested; `x3dh.initiate` (the fail-closed entry point a real caller
should use) and `x3dh.generateSignedPreKey` work end-to-end. Note:
XEdDSA here is the SPEC variant (signer's Edwards sign bit forced to 0);
deployed libsignal ships a documented deviation (sign bit smuggled in
`s`'s top bit) — the two are wire-incompatible for ~half of all keys, and
`src/kat_test.zig` pins both facts against libsignal's own test vector.
See [SPEC.md](SPEC.md).

| File | Contents |
|---|---|
| `src/root.zig` | `meta`, flat re-exports of the X3DH surface, dark-tests aggregator |
| `src/x3dh.zig` | Key types (`IdentityKey`/`SignedPreKey`/`OneTimePreKey`/`EphemeralKey`), `PreKeyBundle`/`InitialMessage` codecs, the four-DH + HKDF agreement (`initiateUnverified`/`respond`), fail-closed `initiate`, `generateSignedPreKey` |
| `src/xeddsa.zig` | XEdDSA `sign`/`verify` + `edwardsFromMontgomery` (the sign-0 Montgomery->Edwards recovery), sign-0-convention tests |
| `src/kat_test.zig` | X3DH agreement + codec tests; XEdDSA round-trip/tamper/fail-closed tests; the libsignal known-answer vector (variant-verifier accept + spec-verify reject); std-Ed25519 cross-check; `initiate`/`respond` end-to-end |

## Import

```zig
const signal = @import("signal");
```

## X3DH walkthrough

```zig
// Bob publishes a bundle (server-side; this module doesn't touch transport).
const bob_ik = std.crypto.dh.X25519.KeyPair.generate(io);
const bob_spk = signal.generateSignedPreKey(bob_ik, /* id */ 1, z, io); // z: 64 bytes from io.random
const bob_opk_kp = std.crypto.dh.X25519.KeyPair.generate(io);

const bundle = signal.PreKeyBundle{
    .identity_key = bob_ik.public_key,
    .signed_prekey = bob_spk.key_pair.public_key,
    .signed_prekey_id = bob_spk.id,
    .signed_prekey_signature = bob_spk.signature,
    .one_time_prekey = bob_opk_kp.public_key,
    .one_time_prekey_id = 42,
};

// Alice fetches `bundle`, then initiates.
const alice_ik = std.crypto.dh.X25519.KeyPair.generate(io);
const out = try signal.initiate(allocator, alice_ik, bundle, initial_plaintext_or_ciphertext, io);
defer out.message.deinit(allocator);
// out.agreement.shared_secret / out.agreement.associated_data feed Part 2 (Double Ratchet).
// out.message is what Alice sends Bob over the wire (out.message.toBytes(allocator)).

// Bob, on receiving out.message:
const agreement = try signal.respond(bob_ik, bob_spk, bob_opk, out.message);
// agreement.shared_secret == out.agreement.shared_secret
```

`signal.initiateUnverified` is the same agreement WITHOUT the XEdDSA
signature check — kept for testing the agreement math in isolation;
real callers should use `signal.initiate` (skipping verification breaks
X3DH's mutual-authentication guarantee — see [SPEC.md](SPEC.md)'s threat
model).

## Part 2 boundary

This module's output is exactly `SK` (32 bytes) + `AD` (64 bytes) — spec-
defined, nothing more. `InitialMessage.ciphertext` is an OPAQUE byte slice
this module carries but never produces or interprets: a real caller
encrypts it with a Part-2 Double Ratchet session seeded from `SK`/`AD`, not
with any AEAD this module invokes itself. No ratchet state, message keys,
or header encryption live here.

## Import graph

```
signal → std.crypto.dh.X25519 / std.crypto.ecc.Edwards25519 /
         std.crypto.hash.sha2.Sha512 / std.crypto.kdf.hkdf.HkdfSha256
```

No sibling-module dependency (`deps = .{}`).

## Verify

```
zig build test-signal                       # 31/31 pass (Debug and -Doptimize=ReleaseFast)
zig fmt --check modules/signal/
```

Provenance: see [NOTICE](NOTICE).
