# signal

The Signal Protocol's core cryptographic building blocks, on `std.crypto`.
A three-part arc, all complete — together a usable Signal-style
end-to-end-encrypted session:

- **Part 1: X3DH** — Extended Triple Diffie-Hellman, the asynchronous
  initial key-agreement (signal.org/docs/specifications/x3dh) — plus
  **XEdDSA** (signal.org/docs/specifications/xeddsa), the Montgomery-
  keypair signature scheme X3DH uses to sign a signed prekey.
- **Part 3: PQXDH** — the post-quantum successor to X3DH
  (signal.org/docs/specifications/pqxdh): the same Diffie-Hellman
  agreements plus one **ML-KEM-1024** encapsulation against a signed
  post-quantum prekey, so recorded traffic survives a future quantum
  adversary. Signal has run this by default since 2023, which makes X3DH
  alone the legacy path. **The spec text still names round-3
  Crystals-Kyber-1024 and cites a FIPS 203 draft; deployments use FIPS 203
  final ML-KEM, and the two do not interoperate** — this implements ML-KEM.
- **Part 2: Double Ratchet** — the per-message forward-secret/
  post-compromise-secure ratchet
  (signal.org/docs/specifications/doubleratchet), seeded with X3DH's `SK`
  as its initial root key and `AD` as its per-message associated data.

**Status: Parts 1-3 COMPLETE.** X3DH's DH+HKDF agreement, both wire
codecs (`PreKeyBundle`, `InitialMessage`), and XEdDSA (`xeddsa.sign`/
`xeddsa.verify`, including `xeddsa.edwardsFromMontgomery` — the
Montgomery->Edwards sign-0 point recovery std does not provide) are real
and tested; `x3dh.initiate` (the fail-closed entry point a real caller
should use) and `x3dh.generateSignedPreKey` work end-to-end. The Double
Ratchet (`ratchet.State`: `initAlice`/`initBob`/`encrypt`/`decrypt`) is
real and tested end-to-end seeded from a live X3DH agreement — interleaved
sessions with repeated DH ratchets, out-of-order delivery (within a chain
and across a ratchet boundary), `max_skip` DoS rejection, and a
transactional fail-closed `decrypt`. **Two XEdDSA variants, chosen
explicitly at the call site:** `xeddsa.sign`/`xeddsa.verify` are the SPEC
variant (signer's Edwards sign bit forced to 0); `xeddsa.libsignal.sign`/
`xeddsa.libsignal.verify` are deployed libsignal's variant (natural-sign
key, sign bit smuggled in `s`'s top bit), for a caller that needs to
interoperate with real Signal clients/servers. The two are
wire-incompatible for ~half of all keys, and `src/kat_test.zig` pins
libsignal's own test vector — whose key is itself sign-1 — as an external
anchor accepted byte-exactly by `xeddsa.libsignal.verify` and rejected by
the spec-pure `xeddsa.verify`. See [SPEC.md](SPEC.md).

| File | Contents |
|---|---|
| `src/root.zig` | `meta`, flat re-exports of the X3DH + PQXDH + Double Ratchet surface, dark-tests aggregator |
| `src/x3dh.zig` | Key types (`IdentityKey`/`SignedPreKey`/`OneTimePreKey`/`EphemeralKey`), `PreKeyBundle`/`InitialMessage` codecs, the four-DH + HKDF agreement (`initiateUnverified`/`respond`), fail-closed `initiate`, `generateSignedPreKey` |
| `src/xeddsa.zig` | XEdDSA `sign`/`verify` (spec variant) + `libsignal.sign`/`verify` (deployed-libsignal variant) + `edwardsFromMontgomery` (the sign-0 Montgomery->Edwards recovery both variants share), sign-0-convention + libsignal-variant self-consistency tests |
| `src/ratchet.zig` | Double Ratchet `State` (`initAlice`/`initBob`/`encrypt`/`decrypt`), `Header`/`Message` + header codec, `KDF_RK`/`KDF_CK`, DH + symmetric-key ratchets, `max_skip`-bounded skipped-key store, transactional decrypt; full-session / out-of-order / MAX_SKIP / tamper tests |
| `src/pqxdh.zig` | PQXDH (Part 3): `KemPreKey`, `PreKeyBundle`/`InitialMessage`, the four-DH + ML-KEM-1024 + HKDF agreement (`initiateUnverified`/`respond`), fail-closed `initiate`, `generateKemPreKey`; **no wire codec** — a caller transmitting a PQXDH bundle writes their own |
| `src/interop_vectors.zig` | The Double Ratchet's `KDF_CK`/`KDF_RK` vectors captured from libsignal, and PQXDH's KDF-chain vectors from `scripts/pqxdh-kdf-check.py` — see each block's doc comment for which is which and what class of anchor it is |
| `src/kat_test.zig` | X3DH agreement + codec tests; XEdDSA round-trip/tamper/fail-closed tests; the libsignal known-answer vector as an external anchor exercised against BOTH variants (`xeddsa.libsignal.verify` byte-exact accept + 64-tamper rejection, `xeddsa.verify` reject); std-Ed25519 cross-check; `initiate`/`respond` end-to-end |

## Import

```zig
const signal = @import("signal");
```

## X3DH walkthrough

```zig
// Bob publishes a bundle (server-side; this module doesn't touch transport).
const bob_ik = signal.x3dh.generateKeyPair(io); // fail-closed draw, not std's KeyPair.generate
const bob_spk = signal.generateSignedPreKey(bob_ik, /* id */ 1, z, io); // z: 64 bytes from io.random
const bob_opk_kp = signal.x3dh.generateKeyPair(io);

const bundle = signal.PreKeyBundle{
    .identity_key = bob_ik.public_key,
    .signed_prekey = bob_spk.key_pair.public_key,
    .signed_prekey_id = bob_spk.id,
    .signed_prekey_signature = bob_spk.signature,
    .one_time_prekey = bob_opk_kp.public_key,
    .one_time_prekey_id = 42,
};

// Alice fetches `bundle`, then initiates.
const alice_ik = signal.x3dh.generateKeyPair(io);
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

`x3dh.zig` itself always uses the spec's XEdDSA variant (`xeddsa.sign`/
`xeddsa.verify`) internally — that is a private implementation detail of
this module's own protocol, self-consistent between its own Alice/Bob.
A caller that instead needs to verify a signature FROM a real Signal
client/server (or produce one a real Signal peer can verify) calls
`signal.xeddsa.libsignal.sign`/`signal.xeddsa.libsignal.verify` directly:

```zig
// Verifying a signed prekey signature that came from real Signal:
const ok = signal.xeddsa.libsignal.verify(their_montgomery_pub, signed_prekey_bytes, their_signature);
```

The two variants are wire-incompatible for keys whose natural Edwards
point has sign 1 (~half of all keys) — see [SPEC.md](SPEC.md)'s "Both
variants, chosen explicitly at the call site" section.

## Double Ratchet walkthrough (Part 2)

X3DH's `SK`/`AD` seed a `ratchet.State`. Bob's INITIAL ratchet keypair is
his signed-prekey keypair (the standard Signal binding — the DH key Alice
already mixed into X3DH). Alice always sends first; Bob's first `decrypt`
performs the DH ratchet that gives him a sending chain.

```zig
// Alice (has SK/AD from x3dh.initiate + Bob's signed-prekey public):
var alice = try signal.initAlice(sk, ad, bob_spk_public, io);
defer alice.deinit(allocator);

// Bob (has SK/AD from x3dh.respond + his own signed-prekey keypair):
var bob = signal.initBob(sk, ad, bob_spk_keypair);
defer bob.deinit(allocator);

var msg = try alice.encrypt(allocator, "hello");   // msg.header + msg.ciphertext
defer msg.deinit(allocator);
const pt = try bob.decrypt(allocator, msg.header, msg.ciphertext, io);
defer allocator.free(pt);                          // pt == "hello"
// Now bob.encrypt(...) works (his first decrypt established a sending chain).
```

- **AEAD/KDF instantiation** (the spec leaves these application-defined):
  `KDF_RK` = HKDF-SHA256 (salt = root key, 64-byte `RK'‖CK` output);
  `KDF_CK` = HMAC-SHA256 with the spec's `0x01`/`0x02` constants;
  **AEAD = ChaCha20-Poly1305** over a per-message key+nonce HKDF-expanded
  from the message key, AAD = `AD ‖ header`. The spec's own example uses
  AES-256-CBC + HMAC-SHA256, but explicitly permits any AEAD. See
  [SPEC.md](SPEC.md).
- **Security**: forward secrecy (each message key is single-use and
  `secureZero`'d after use; chain keys advance one-way) + post-compromise
  security (each DH ratchet re-randomizes the root key). `decrypt` is
  **transactional** — a tampered message never advances or corrupts the
  session (fail-closed).
- **Out of scope**: header encryption (HE) and a stable on-disk
  session-persistence format. See [SPEC.md](SPEC.md). (PQXDH seeding was in
  this list until 2026-08-22 and is now Part 3 — seed the ratchet with
  `PqAgreement.ratchetAssociatedData()`, not the full 1632-byte AD; see the
  walkthrough below for why they differ.)

## PQXDH walkthrough (Part 3)

The flow is X3DH's with one addition, and one seam worth knowing about
before you hit it.

```zig
// Bob, ahead of time. Every KEM prekey is signed — one-time and
// last-resort alike, unlike curve one-time prekeys, because a curve prekey
// is authenticated by the DH against Bob's identity key and a KEM prekey
// has nothing equivalent.
const bob_kem = signal.generateKemPreKey(bob_ik, 100, true, z, io);

// Alice, with Bob offline. Verifies BOTH signatures before deriving
// anything, and distinguishes which one failed: they are different keys on
// different rotation schedules.
const opened = try signal.pqInitiate(gpa, alice_ik, bundle, "", io);

// Seed the ratchet — with the 64-byte form, not the full AD.
var alice = try signal.initAlice(
    opened.agreement.shared_secret,
    opened.agreement.ratchetAssociatedData(),
    bob_spk.key_pair.public_key,
    io,
);
```

**Why two associated-data values.** PQXDH's `AD` is 1632 bytes:
`Encode(IKA) || Encode(IKB) || Encode(PQPKB)`. The third term is required
because ML-KEM's ciphertext does not commit to the public key it was
produced under — without it, an attacker who can swap Bob's published KEM
prekey does so without the authenticated data changing. That binding
matters for the initial message, which is where the KEM key is used.
Carrying 1568 extra bytes into every subsequent ratchet message would
protect a key that no longer participates, so the ratchet keeps X3DH's
64-byte `Encode(IKA) || Encode(IKB)`, and `ratchetAssociatedData()` is the
bridge. Passing the full value does not compile, which is the intent.

**What anchors this.** Less than the rest of this module, and the
difference is stated rather than smoothed over: Signal publishes no
byte-exact PQXDH vectors (checked 2026-08-22 — neither the spec page nor
libsignal). XEdDSA carries libsignal's own vector, and the
composition is checked against an independent implementation of the same
arithmetic (`scripts/pqxdh-kdf-check.py --check`). **ML-KEM-1024 itself is
unanchored** — std's three `NIST KAT test` blocks all cover `d00.Kyber*`,
the round-3 variant this module explicitly does not implement, while
`nist.MLKem1024` gets only a self round trip. This paragraph used to claim
those KATs as the KEM's anchor; they belong to the other algorithm. A round trip cannot catch a misplaced KEM
secret — Alice and Bob would agree on the wrong answer together — so the
wrong answer is pinned as a value the code must never produce.

## Import graph

```
signal → std.crypto.dh.X25519 / std.crypto.ecc.Edwards25519 /
         std.crypto.hash.sha2.Sha512 / std.crypto.kdf.hkdf.HkdfSha256 /
         std.crypto.auth.hmac.sha2.HmacSha256 /
         std.crypto.aead.chacha_poly.ChaCha20Poly1305
```

No sibling-module dependency (`deps = .{}`).

## Verify

```
zig build test-signal                       # green (Debug and -Doptimize=ReleaseFast)
zig fmt --check modules/signal/
```

Provenance: see [NOTICE](NOTICE).
