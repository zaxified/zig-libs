# bolt8 — SPEC

Lightning BOLT#8 encrypted transport; see [README.md](README.md) for
purpose and API. Provenance: see [NOTICE](NOTICE).

## Noise-reuse decision (the investigation this module's shape hinges on)

BOLT#8 instantiates `Noise_XK_secp256k1_ChaChaPoly_SHA256` on top of the
Noise Protocol Framework. This repo already ships a COMPLETE, tested
generic Noise implementation (`../noise`) — the question is whether this
module can drive that implementation directly, or must implement its own
handshake driver on top of a narrower reuse surface. Two separate gaps
were investigated; only one turned out to be real.

### 1. The DH width split — NOT a problem

BOLT#8's `ECDH(k, P) = SHA256(compressed(k·P))` returns a **32-byte**
value, but its public keys are **33-byte compressed** secp256k1 points —
so `DHLEN` (pubkey width) and the DH-output width part ways, unlike
"vanilla" Noise's X25519 instantiation where both are 32 bytes.

Reading `noise/src/state.zig`'s `Suite(DH, Cipher, Hash)` line by line
settles this cleanly:

- `Suite.DHLEN = DH.public_length` — used ONLY for sizing `rs`/`re`
  (`?[DHLEN]u8`, the REMOTE PUBLIC KEY fields) and for how many bytes
  `writeMessage`/`readMessage`'s `.e`/`.s` tokens copy to/from the wire.
  This is exactly the 33-byte pubkey width BOLT#8 needs — a secp256k1 `DH`
  adapter with `public_length = 33` sizes these correctly.
- The DH **output** never appears as a `[DHLEN]u8`-shaped value anywhere.
  `HandshakeState.mixDh` does `var shared = DH.scalarmult(local.secret_key,
  remote_pub) catch ...; self.symmetric_state.mixKey(&shared);` —
  `scalarmult`'s return type is whatever the `DH` type declares (a plain
  Zig value, sized however that type wants), and `mixKey(input_key_material:
  []const u8)` treats it as an OPAQUE byte slice via `&shared`. Nothing
  hardcodes `DHLEN` for the DH output.
- `SymmetricState` itself (`mixKey`/`mixHash`/`encryptAndHash`/
  `decryptAndHash`/`split`) never references `DH` or `DHLEN` AT ALL — it
  operates purely on `[]const u8`/`[HASHLEN]u8` values.

**Conclusion: a secp256k1 DH adapter (`public_length = 33`, `scalarmult`
returning `[32]u8`) is fully compatible with `noise`'s DH-width handling.**
This part of the investigation would have supported driving the handshake
through `noise.HandshakeState` directly (option A in the task brief).

### 2. `HandshakeState.initialize`'s protocol-name lookup — a REAL blocker

`state.zig`'s `dhName(comptime T: type) []const u8` (used inside
`HandshakeState.initialize` to build the `"Noise_" ++ pattern.name ++ "_"
++ dhName(DH) ++ ...` protocol-name string per spec §8) is:

```zig
fn dhName(comptime T: type) []const u8 {
    if (T == std.crypto.dh.X25519) return "25519";
    @compileError("noise: no spec §8 protocol name for DH type " ++ @typeName(T));
}
```

This recognizes **only** `std.crypto.dh.X25519`. Instantiating
`noise.Suite(Secp256k1DH, ChaChaPoly, SHA256)` itself compiles fine (the
struct's other top-level decls — `DHLEN`, `KeyPair`, the comptime
assertions — never call `dhName`), and `Suite.SymmetricState` is fully
usable standalone. But the MOMENT any code path calls
`Suite.HandshakeState.initialize(...)`, `dhName(Secp256k1DH)` executes at
comptime and hits its `@compileError` branch — this is not a runtime
failure to catch, it is a **build failure**, unconditionally, for any `DH`
other than X25519. `noise/src/patterns.zig` also doesn't define an `XK`
pattern (only NN/NK/XX/IK), which would additionally need a local
`HandshakePattern` value — moot, since this module never reaches the code
path that would consult one.

Empirically verified (not just read) before committing to this shape: a
throwaway `noise.Suite(FakeDH, ChaChaPoly, SHA256)` with a hand-rolled
33-byte-pubkey `FakeDH` type compiles and its `SymmetricState` runs fine
standalone — confirming `Suite(DH,...)`'s non-`HandshakeState` surface
never touches `dhName`.

**Decision: (B).** This module drives the three-act `Noise_XK` handshake
itself (`handshake.zig`'s `Initiator`/`Responder`), reusing ONLY
`noise.Suite(dh, ChaChaPoly, SHA256).SymmetricState` — never
`HandshakeState`. `dh.zig` (this module's own file) IS the `DH` type
parameter passed to `Suite(...)` (it supplies `public_length`, `KeyPair`,
and a `scalarmult` alias for API-shape parity, even though `scalarmult` —
and therefore `dhName` — is never actually invoked).

### Why this split is a genuine free lunch, not just "it compiles"

Once `HandshakeState` is off the table, the natural worry is that BOLT#8's
per-act nonce/key bookkeeping (temp_k1/temp_k2/temp_k3, the exact nonce
each is used at) has to be hand-rolled and could easily drift from the
spec. It doesn't, because `SymmetricState`'s own state machine ALREADY
encodes the right invariants, as long as one instance is threaded through
all three acts in order (exactly mirroring how `HandshakeState.
writeMessage`/`readMessage` process one pattern's tokens per call):

- **Act Three's `c` field is encrypted at nonce 1, not 0** (BOLT#8: `c =
  encryptWithAD(temp_k2, 1, h, s.pub)`) — this falls out automatically
  from `CipherState`'s auto-incrementing nonce counter, PROVIDED the
  driver does not re-key between Act Two's zero-payload `encryptAndHash`
  (nonce 0, using `temp_k2`) and Act Three's static-key `encryptAndHash`
  (nonce 1, same `temp_k2` — no intervening `mixKey`). This is the single
  easiest correctness sinkhole for whoever fills in `genAct3`/`readAct3`
  — flagged explicitly in both functions' doc comments.
- **`rck = sck = ck`** (BOLT#8 Act Three step 8/step 11): `SymmetricState.
  split()` reads `self.ck` to derive the two transport `CipherState`s but
  does **not** overwrite it (unlike `mixKey`/`mixKeyAndHash`, which both
  do `self.ck = out[0]`) — so `ss.ck` immediately after calling `split()`
  IS, with zero extra bookkeeping, exactly the value BOLT#8 wants seeded
  into `sck`/`rck`. `handshake.HandshakeResult.ck` is just `ss.ck` read at
  that point.
- **The message-key rotation ratchet is ALSO just `SymmetricState.
  mixKey`**, reused a second time post-handshake: BOLT#8's `ck', k' =
  HKDF(ck, k)` is the exact same three-line formula `mixKey` already
  implements (`out = HKDF(ck, ikm, 2); ck = out[0]; cipher_state =
  initializeKey(out[1])` — which also resets the nonce to 0, covering the
  spec's own step 3 "reset the nonce" for free). `transport.zig`'s
  `Direction.rotate()` builds a throwaway `SymmetricState` shell seeded
  with `(chain, cipher.k)` and calls `.mixKey(&cipher.k)` — this is why
  `transport.zig` needed **zero** stubbing: the "rotation ratchet" is not
  new crypto, it is the same primitive noise already implements, called a
  second time after the handshake ends.

This is also why the STUBBED surface is exactly as narrow as it is: only
the six functions that decide **when** each DH happens and **what** gets
mixed into the running key at each of the three acts
(`Initiator.genAct1`/`.readAct2`/`.genAct3`,
`Responder.readAct1`/`.genAct2`/`.readAct3`) are reserved — everything
else in this module (`dh.zig`'s ECDH primitive, `act.zig`'s framing,
`Initiator.init`/`Responder.init`'s pre-Act-One transcript setup, all of
`transport.zig`) is real, because none of it required deciding anything
BOLT#8 doesn't already spell out byte-for-byte, or was already solved by
`noise`'s existing, KAT-verified `SymmetricState`.

## Design & framing

- **Act framing** (`act.zig`): fixed 50/50/66-byte layouts per "Handshake
  Exchange". `e_pub`/the zero-length-AEAD `tag` travel separately
  (Noise's `e` token is never itself encrypted); Act Three's `c` is the
  33-byte encrypted static key PLUS its 16-byte tag (49 bytes total),
  followed by a second, independent 16-byte tag `t`. The leading version
  byte (`0`) is checked before anything else — "Handshake Versioning":
  clients MUST reject an unrecognized version.
- **`Secp256k1DH` adapter** (`dh.zig`): `public_length = 33`; `KeyPair`
  (32-byte secret / 33-byte SEC1-compressed public, via `std.crypto.ecc.
  Secp256k1.basePoint.mul` + `.toCompressedSec1()` — the same chain this
  repo's own `sphinx`/`bip340` modules already use and KAT-verify);
  `dh()` = `SHA256(compressed(secret · fromSec1(remote_pub)))` exactly per
  BOLT#8's `ECDH(k, rk)` definition.
- **Prologue / protocol name**: `h = SHA256("Noise_XK_secp256k1_
  ChaChaPoly_SHA256")` (`SymmetricState.initializeSymmetric`), `ck = h`,
  `h = SHA256(h || "lightning")` (`.mixHash(prologue)`), then both sides
  mix in the responder's static key from their own perspective
  (`Initiator.init`/`Responder.init`) — all REAL, all pure
  `SymmetricState` calls with no DH/AEAD involved.
- **Transport framing** (`transport.zig`): `2-byte length ‖ 16-byte tag ‖
  encrypted payload ‖ 16-byte tag`, big-endian length, zero-length AD,
  ChaCha20-Poly1305 nonce = 32 zero bits ‖ little-endian 64-bit counter
  (identical convention to the handshake's own AEAD — `noise.CipherState`
  already implements this exact nonce encoding, see `../noise/src/
  state.zig`'s `nonceBytes`).
- **Key rotation** (`transport.zig`'s `Direction.rotate`/`.maybeRotate`):
  triggers when a direction's `CipherState.n` reaches 1000 (every 500
  messages, since each message consumes two nonce values — one for the
  length prefix, one for the payload); see "genuine free lunch" above for
  why this is real, not stubbed.

## Threat model

- **Static-key hiding is `Noise_XK`'s entire point**: the responder's
  static key is never transmitted (known out-of-band); authentication is
  implicit via the `es`/`ee`/`se` DH chain plus a MAC check at each act. A
  MAC failure at ANY act MUST terminate the connection immediately with no
  further messages (BOLT#8's own repeated wording) — `handshake.
  HandshakeError.DecryptionFailed` is the fail-closed signal for this;
  `readAct1`/`readAct2`/`readAct3` all propagate it directly (no
  recovery/retry path exists), KAT-verified against the spec's own
  bad-MAC vectors.
- **Public-key parsing is a real attack surface even before any AEAD
  check runs**: `dh.dh()` rejects a malformed remote point
  (`error.InvalidPublicKey`) via `Secp256k1.fromSec1` — BOLT#8's own
  `*_BAD_PUBKEY` vectors feed an uncompressed-form (`0x04`) prefix into a
  still-33-byte slot specifically to probe this. `dh.zig`'s tests exercise
  this for real, independent of the handshake driver.
- **Act Three's `rs` can decrypt successfully (valid MAC) yet still be an
  invalid point** ("transport-responder act3 bad rs test") — the AEAD
  check passing is NOT sufficient; `Responder.readAct3` validates the
  recovered 33 bytes parse as a valid secp256k1 point (the `se` DH's own
  `fromSec1` step, run BEFORE the key is stored) — KAT-verified in
  `kat_test.zig` against `act3_bad_rs_message`, with the underlying
  parse-rejection additionally real-tested standalone in `dh.zig`.
- **Nonce-continuity is the single easiest place a from-scratch
  reimplementation of this handshake goes subtly wrong** (see "genuine
  free lunch" above) — get it wrong and every downstream ciphertext byte
  changes silently (it still "compiles and runs", it just never
  interoperates with a real Lightning node). Both `genAct3`/`readAct3`'s
  doc comments call this out explicitly as the load-bearing detail.
- **Message-length limits**: `transport.max_message_len = 65535` is
  enforced in `Transport.sendMessage` before any encryption runs
  (`error.MessageTooLong`) — BOLT#8: "simplifies testing, makes memory
  management easier, and helps mitigate memory-exhaustion attacks."
- **Out of scope for this module**: the actual TCP/framing transport
  loop (reading exactly N bytes off a real socket — left to the caller,
  same posture as this repo's `ssh` module's transport layer), and
  anything above the Lightning-message byte boundary (message-type
  dispatch, `init`/`ping`/gossip semantics — BOLT#1/BOLT#7 territory, not
  this module's concern).

## TODO(fable) — done record (fill-in pass completed 2026-07-12)

All six `handshake.zig` act-driver stubs were implemented in the
checklist's dependency order — each is exactly its doc comment's BOLT#8
recipe (one `dh.dh` ECDH mixed via `SymmetricState.mixKey`, one
`encryptAndHash`/`decryptAndHash`, plus the act's `mixHash` steps) — and
every formerly-`SkipZigTest` KAT assertion in `kat_test.zig` was
re-enabled; the module now carries **zero skips**:

1. **`Initiator.genAct1`** — `mixHash(e.pub)` → `es = ECDH(e.priv, rs)` →
   `mixKey(es)` → `encryptAndHash("")`. Reproduces
   `kat_vectors.act1_bytes` byte-exact (KAT-injected ephemeral via the
   test-build-only `genAct1WithEphemeral` hook; `genAct1` itself always
   draws from its `Ephemeral` argument — see "RNG seam" below).
2. **`Responder.readAct1`** — mirror (`es = ECDH(s.priv, re)`),
   `decryptAndHash(tag)` fail-closed. Accepts `act1_bytes`, rejects
   `act1_bad_mac` with `error.DecryptionFailed`.
3. **`Responder.genAct2`** — `mixHash(e.pub)` → `ee = ECDH(e.priv, re)` →
   `mixKey(ee)` → `encryptAndHash("")`. Reproduces `act2_bytes`
   byte-exact.
4. **`Initiator.readAct2`** — mirror (`ee = ECDH(e.priv, re)`). Accepts
   `act2_bytes`, rejects `act2_bad_mac` with `error.DecryptionFailed`.
5. **`Initiator.genAct3`** — `encryptAndHash(ls.pub)` at nonce 1 (the
   temp_k2 nonce-continuity property: same `SymmetricState` instance, no
   intervening `mixKey` — see "genuine free lunch" above) → `se =
   ECDH(ls.priv, re)` → `mixKey(se)` → `encryptAndHash("")` → `split()`
   with `sk = pair[0].k`, `rk = pair[1].k`, `ck = ss.ck` (unmutated by
   `split`), `handshake_hash = ss.h`. Reproduces `act3_bytes` byte-exact
   AND `HandshakeResult.{sk,rk,ck}` == `{init_sk, init_rk,
   ck_temp_k3[0]}`.
6. **`Responder.readAct3`** — `decryptAndHash(c)` at nonce 1 recovers
   `rs`; the recovered key is validated by the `se = ECDH(e.priv, rs)`
   call itself (`Secp256k1.fromSec1` → `error.InvalidPublicKey`) BEFORE
   being stored into `self.rs_pub`; then `mixKey(se)` →
   `decryptAndHash(t)` → `split()` with the assignment order SWAPPED
   (`rk = pair[0].k`, `sk = pair[1].k`). Accepts `act3_bytes` (its
   `rk`/`sk` == the initiator's `sk`/`rk`, both == the published
   vectors; recovered `rs` == `init_ls_pub`; final `h` matches the
   initiator's), rejects `act3_bad_ciphertext`/`act3_bad_tag`
   (`DecryptionFailed`) and `act3_bad_rs_message` (`InvalidPublicKey`
   after a SUCCESSFUL decrypt, `rs_pub` left unset).

`kat_test.zig`'s full-handshake test additionally closes the loop through
`transport.zig`: `Transport`s built from BOTH sides' fresh
`HandshakeResult`s round-trip a `"hello"` (initiator's first frame ==
the published message-0 vector, responder decrypts it back).

## Verification

- KAT oracle: the official BOLT#8 "Appendix A: Transport Test Vectors",
  fetched directly from `lightning/bolts`, `08-transport.md` (raw GitHub,
  `master` branch). Embedded in `src/kat_vectors.zig` — see `NOTICE` for
  the exact fetch provenance. Every hex constant was independently
  verified (byte length + exact substring match against the fetched file)
  before transcription, not merely eyeballed.
- Independent cross-check: the pre-Act-One `ck` (`kv.ck_after_init`) and
  the full pre-Act-One transcript hash `h` (`handshake.zig`'s own test)
  were additionally recomputed from scratch via Python `hashlib` directly
  from BOLT#8's "Handshake State Initialization" formulas — not merely
  re-run through this module's own Zig code — confirming the spec's
  published `ck` intermediate independently.
- Real, exercised today (Debug + ReleaseFast, zero skips anywhere):
  `Secp256k1DH.KeyPair.generateDeterministic` reproduces all 4 published
  identities' public keys; `dh.dh` reproduces all 3 published per-act ECDH
  outputs (`es`/`ee`/`se`), in BOTH directions, and rejects 2 malformed
  points; `act.Act1`/`.Act2`/`.Act3` round-trip all 3 published wire
  messages byte-exact and reject 6 published short-read/bad-version
  negative vectors; `Initiator.init`/`Responder.init` agree with each
  other and match an independent oracle; `transport.Direction.rotate`
  reproduces both published rotation intermediates byte-exact;
  `Transport.sendMessage` reproduces all 6 published message-test outputs
  (indices 0/1/500/501/1000/1001) across both key-rotation boundaries; a
  full 1002-message send/receive round-trip decrypts every message back
  to `"hello"`; a tampered transport ciphertext fails closed with
  `error.DecryptionFailed`.
- Crypto-level (formerly reserved, now real — see the done record above):
  the full act1->act2->act3 walk end-to-end (both sides, byte-exact,
  including the transport keys and a post-handshake `"hello"` round-trip
  matching the published message-0 vector), and all five crypto-dependent
  negative vectors (`act2_bad_mac`, `act1_bad_mac`, `act3_bad_ciphertext`,
  `act3_bad_tag`, `act3_bad_rs_message`) — all in `kat_test.zig`, zero
  `SkipZigTest` remaining.

## RNG seam (B6 audit, 2026-08-12)

BOLT#8's Act One `e` is the initiator's only per-session secret input: the
Act-One wire bytes and `es = ECDH(e.priv, rs)` are pure functions of it. Two
shapes in the original driver let a consumer fix that value without ever
deciding to.

- `Initiator.e`/`Responder.e` were **public input fields** and the act steps
  did `self.e orelse dh.KeyPair.generate(random)`. Assigning the field made the
  `random` argument dead code, so every Act One carried the same `e_pub` —
  cross-session linkability, a constant `es`, no initiator forward secrecy.
  The fields are now named `ephemeral` and are pure **outputs**: `genAct1`/
  `genAct2` always draw. The KAT injection Appendix A needs moved to
  `genAct1WithEphemeral`/`genAct2WithEphemeral`, which `@compileError` outside
  a test build (`assertTestOnly`) — production cannot express a pinned
  ephemeral at all.
- The generator argument is now `Ephemeral`, a tagged union with a `csprng`
  arm and a `seeded_for_test` arm and a private `source()` accessor (the same
  shape as `dtls`'s `Connection.Entropy`). `std.Random` is a vtable, so
  `DefaultPrng.init(0).random()` and a real CSPRNG are indistinguishable at a
  bare parameter; naming the arm is what makes the choice a decision. This is
  *fail-visible*, not fail-closed: nothing checks what is inside `.csprng`.

Both acts are additionally guarded by a linear state machine
(`start → awaiting_act2 → ready_act3 → done` and the responder's mirror), so a
second `genAct1` on one object is `error.WrongState` rather than a silent reuse
of the cached share.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** official BOLT#8 Appendix A Transport Test Vectors (NOTICE)
