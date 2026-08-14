# signal — SPEC (X3DH + XEdDSA + Double Ratchet)

X3DH (signal.org/docs/specifications/x3dh) + XEdDSA
(signal.org/docs/specifications/xeddsa) + Double Ratchet
(signal.org/docs/specifications/doubleratchet); see [README.md](README.md)
for purpose and API. Provenance: see [NOTICE](NOTICE).

**Status: Part 1 + Part 2 complete.** `x3dh.zig`'s DH+HKDF agreement, both
wire codecs, and `xeddsa.zig`'s `sign`/`verify` (spec variant, with the
Montgomery->Edwards sign-0 recovery, `edwardsFromMontgomery`) PLUS
`xeddsa.libsignal.sign`/`verify` (deployed-libsignal variant, for
interop with real Signal), plus `ratchet.zig`'s full Double Ratchet
(`State` + `initAlice`/`initBob`/`encrypt`/`decrypt`, `KDF_RK`/`KDF_CK`,
the DH + symmetric-key ratchets, `max_skip`-bounded out-of-order
handling, transactional fail-closed `decrypt`) are implemented and
tested — green in Debug and ReleaseFast, including a libsignal
known-answer vector pinned against BOTH XEdDSA variants; see
"Verification" below.

## Design

- **Source of truth**: the public X3DH and XEdDSA specification texts
  (Signal Foundation). Both are self-contained: X3DH depends only on a DH
  function + a KDF + (for the signed-prekey signature) a signature scheme
  over the SAME keys the DH uses — XEdDSA is that signature scheme, chosen
  by Signal specifically so identity keys don't need a SEPARATE Ed25519
  keypair alongside their X25519 one.
- **Four DHs, one HKDF** (`x3dh.zig`): `DH1 = DH(IKA, SPKB)`, `DH2 =
  DH(EKA, IKB)`, `DH3 = DH(EKA, SPKB)`, `DH4 = DH(EKA, OPKB)` (only if
  Bob's bundle carried a one-time prekey). `SK = HKDF-Expand(HKDF-
  Extract(zeroes, F || DH1 || DH2 || DH3 [|| DH4]), info)`. `F` = 32 bytes
  of `0xFF` (X25519's domain-separation prefix, spec-fixed). `info` is
  THIS module's own constant (`x3dh.x3dh_info`) — the spec deliberately
  leaves it application-defined.
- **`initiateUnverified` vs `initiate`**: `x3dh.initiateUnverified` runs
  the real DH+HKDF agreement WITHOUT checking `PreKeyBundle`'s XEdDSA
  signature first; `x3dh.initiate` checks it (fail-closed,
  `xeddsa.verify`) then calls `initiateUnverified`. The split keeps the
  agreement's own correctness testable independent of signature
  verification. **`initiate`, not `initiateUnverified`, is the function a
  real caller should use** — skipping verification breaks X3DH's
  mutual-authentication guarantee (see "Threat model" below).
- **Symmetry, not two implementations**: `initiateUnverified` (Alice) and
  `respond` (Bob) both call the SAME private `dh`/`deriveSharedSecret`
  helpers in `x3dh.zig`; the two sides land on the identical `SK` purely
  because `X25519.scalarmult(a_priv, b_pub) == X25519.scalarmult(b_priv,
  a_pub)` (ordinary DH commutativity) — there is no separate "Bob's KDF"
  code path to accidentally drift from Alice's.
- **`PreKeyBundle`/`InitialMessage` codecs** (`x3dh.zig`): plain
  fixed-header byte layouts (169 bytes / 77-byte-header +
  variable-length ciphertext) — REAL, no crypto judgment beyond `has_opk`
  flag validation and a declared-vs-actual ciphertext-length check.
- **XEdDSA's core trick** (`xeddsa.zig`): a signer's Montgomery (X25519)
  keypair is birationally mapped to an Edwards25519 point, with the sign
  bit of the Edwards public key FORCED to a fixed convention (0/even) by
  negating the private scalar if needed — see `xeddsa.zig`'s
  `calculateKeyPair`. This lets ONE keypair serve both as an X25519 DH key
  (used directly, unmodified, everywhere in `x3dh.zig`) and — via this
  conversion — as a signing key, without publishing two separate public
  keys. `std.crypto.dh.X25519`/`std.crypto.ecc.Edwards25519` do not expose
  this conversion in the Montgomery-to-Edwards direction (std has the
  REVERSE, `Curve25519.fromEdwards25519`, used by `X25519.KeyPair.
  fromEd25519`) — `xeddsa.edwardsFromMontgomery` (`y = (u-1)/(u+1)`, then
  decompress with sign bit 0) is the module's fill for that gap.
- **Both variants, chosen explicitly at the call site** (`xeddsa.zig`'s
  module doc comment): the XEdDSA paper forces the signer's Edwards key
  to sign 0 and leaves `s` a canonical scalar; DEPLOYED libsignal (C,
  Java, and current Rust — its source says so explicitly) instead signs
  with the natural-sign key and smuggles the sign bit in `s`'s top bit.
  The two are wire-incompatible for the ~half of keys whose natural
  Edwards point has sign 1. Top-level `sign`/`verify` implement the
  PAPER; the `libsignal` namespace (`xeddsa.libsignal.sign`/
  `xeddsa.libsignal.verify`) implements the DEPLOYED variant, for a
  caller that needs to interoperate with real Signal clients/servers
  rather than a spec-faithful peer. There is no silently-chosen default —
  a caller must name one or the other. `kat_test.zig` pins libsignal's
  own published test vector (whose key is itself sign-1, the exact case
  the spec variant cannot handle) as an EXTERNAL ANCHOR against BOTH:
  `xeddsa.libsignal.verify` must accept it byte-exactly (with all 64
  single-byte tampers rejected), and the spec-pure `xeddsa.verify` must
  reject the identical bytes.

## Threat model / limits

- **X3DH gives mutual authentication of the FIRST message + forward
  secrecy of `SK`** (spec's own headline properties), CONDITIONAL on
  `initiate` actually verifying the signed prekey's signature
  (`xeddsa.verify`) before trusting `DH1`/`DH3` — an unverified `SPKB`
  lets an active attacker substitute their own signed prekey and mount a
  man-in-the-middle. `initiateUnverified` exists ONLY for testing the
  agreement math itself; shipping it in place of `initiate` in a real
  client is a protocol-breaking bug, not a supported configuration.
- **XEdDSA key-reuse caveat** (the scheme's own documented trade-off, not
  a flaw introduced by this module): using the SAME 32-byte scalar as
  both an X25519 DH private key and an XEdDSA signing key is safe ONLY
  because XEdDSA's hash-domain separation (`hash1`'s `0xFE || 0xFF*31`
  prefix vs plain `hash`'s no-prefix — see `xeddsa.zig`'s `sign` doc
  comment step 2 vs step 4) is specifically designed to prevent a
  signature-forgery oracle from being built out of DH shared-secret
  computations (or vice versa) on the same key. A from-scratch
  implementation that reuses X25519 keys for signing WITHOUT this
  domain-separated hashing does NOT get this property for free — it is
  the entire reason XEdDSA exists as a distinct scheme rather than "just
  use `X25519.KeyPair.fromEd25519` and sign with plain Ed25519" (which
  would require a SEPARATE Ed25519 keypair per identity, the thing XEdDSA
  avoids).
- **`respond`'s id-mismatch caveat**: `respond` takes `bob_opk: ?OneTimePreKey`
  as a caller-supplied value; it does not itself check that
  `bob_opk.?.id == alice_initial.one_time_prekey_id`. A production
  integration MUST look up the one-time prekey BY the id Alice's message
  names (and treat "Alice named an id we don't have — already consumed,
  or never existed" as its own error, before calling `respond`) — this
  module's `respond` trusts its caller to have already resolved that
  lookup correctly; see `x3dh.zig`'s `respond` doc comment.
- **Forward secrecy of `SK` degrades gracefully without an OPK**: per
  spec, if Bob's one-time-prekey queue is exhausted, X3DH proceeds with
  only 3 DHs (`DH4` and its term simply omitted) — `initiateUnverified`/
  `respond` both handle this (`PreKeyBundle.one_time_prekey == null`)
  without a separate code path; the spec documents this as a REDUCED, not
  absent, security property for that one session (an attacker who
  compromises `SPKB` after the fact gains slightly more from a 3-DH
  session than a 4-DH one — see the spec's own "Security considerations").
- **Constant-time**: `X25519.scalarmult`/`X25519.KeyPair.generateDeterministic`
  (which `x3dh.generateKeyPair` wraps around a fail-closed seed draw) are
  std's own constant-time-on-secret-material primitives (RFC 7748
  clamped Montgomery ladder) — this module performs no additional
  secret-dependent branching of its own in the DH/HKDF path.
  `xeddsa.sign` handles the secret scalar with `Edwards25519.scalar`'s
  constant-time ops, **`ct25519.mulBase`** and a BRANCHLESS
  masked select for the negate-if-sign-1 step. This line used to read
  "a constant-time `basePoint.mul`", meaning std's; std's ladder is
  constant-time and then ends with `try q.rejectIdentity()`, a branch on
  a scalar-derived value, which forced a `catch @panic(...)` on both of
  this module's secret base multiplications (the key scalar `a` and the
  nonce `r`). `ct25519.mulBase` is that ladder without the tail. Neither
  panic could ever fire — a clamped seed lies in `[2^254, 2^255)` and is
  divisible by 8, and the smallest multiple of `L` that is divisible by 8
  is `8L > 2^255` (pinned by a test) — so the reachable defect was the
  leak, not the abort. (The sign bit itself is public-equivalent — it is
  a deterministic function of the public key pair `±A`, and deployed
  libsignal transmits it in every signature.) Signing
  secrets are `std.crypto.secureZero`d on exit. `xeddsa.verify` operates
  on public inputs only (variable-time `mulDoubleBasePublic`, like std's
  own Ed25519 verifier) and fails closed on every malformed input.
- **No replay/freshness protection is this module's job**: X3DH itself
  provides none beyond "OPK consumed once" (a server-side bookkeeping
  concern, not cryptographic); session continuity/replay protection is
  Part 2's (Double Ratchet's) responsibility.

## XEdDSA implementation notes

`xeddsa.zig` implements the spec's construction on std primitives only,
in two variants sharing the same `Signature`/`RandomData` wire types and
the same `edwardsFromMontgomery` conversion:

1. **`sign`/`verify` (spec variant)** — `sign`: Montgomery-seed ->
   sign-0-forced Edwards keypair (`calculateKeyPair`: clamp, reduce,
   `basePoint.mul`, branchless negate-if-sign-1); `hash1`-domain-separated
   nonce (`SHA-512(0xFE || 0xFF*31 || a || M || Z)`, wide-reduced mod L,
   over the possibly-negated scalar `a` per spec); `R = r·B`;
   plain-`SHA-512`-domain challenge `h = hash(R || A || M) mod L`;
   `s = r + h·a mod L` (`scalar.mulAdd`); return `R || s`, `s` always
   canonical (`< L`). `verify`: `edwardsFromMontgomery` recovers the
   sign-0 Edwards point `A` from the Montgomery `u`-coordinate alone
   (`y = (u-1)/(u+1)` via `Fe` ops, then `Edwards25519.fromBytes` with
   sign bit 0 picks the even-`x` root and rejects twist points),
   fail-closed on non-canonical `u` and the `u = p-1` pole; then
   `rejectIdentity`/`rejectLowOrder`, `scalar.rejectNonCanonical(s)` (the
   FULL 32 bytes — a set top bit puts `s >= 2^255 > L` and is rejected,
   which is exactly what makes a deployed-variant sign-1 signature land
   here), and the standard Ed25519-shaped `sB - hA == R` cofactorless byte
   comparison (`Edwards25519.mulDoubleBasePublic`). Every failure path
   returns `false`; nothing panics on attacker input.
2. **`libsignal.sign`/`libsignal.verify` (deployed variant)** — identical
   shape, EXCEPT: `naturalKeyPair` skips the sign-0 forcing (the scalar
   and public point are used exactly as clamp+reduce produces them); the
   natural public point's sign bit is OR'd into `sig[63]`'s top bit after
   `mulAdd` (safe because a canonical scalar is `< L < 2^253`, so that bit
   is always free beforehand); `libsignal.verify` reads `sig[63] >> 7`,
   negates the sign-0-recovered `A` back to the natural-sign point if the
   bit is 1, and — the canonicality check that MUST differ from variant
   1 above — masks the bit off `s` (`s[31] &= 0x7F`) BEFORE calling
   `scalar.rejectNonCanonical`, since the bit is not part of the scalar.
   Skipping the mask would reject every genuine sign-1 signature as
   non-canonical; masking unconditionally without first reading the bit
   (or reading it after masking) would silently accept a corrupted sign
   bit instead of checking against the correct `A`.

Test-vector status: the XEdDSA spec text publishes no numeric vector.
`src/kat_test.zig` embeds libsignal's own `test_curve25519_signature`
vector (numeric facts from libsignal-protocol-c's test suite; see
`NOTICE`) as an EXTERNAL ANCHOR exercised against BOTH variants: the
module's shipped `xeddsa.libsignal.verify` must accept it byte-exactly
with all 64 single-byte tampers rejected (this vector's key is sign-1,
so this is also the positive anchor for a natural-sign-1 key — the case
the spec variant cannot handle), and the module's spec-pure `verify` must
reject the identical bytes (variant incompatibility, pinned). `sign` is
additionally cross-checked against `std.crypto.sign.Ed25519`'s
independent verifier (an XEdDSA challenge hash is byte-identical to
Ed25519's, so a spec-pure XEdDSA signature must verify as Ed25519 under
the recovered sign-0 `A`). `xeddsa.zig`'s own in-file tests additionally
cover `libsignal.sign`/`verify` self-consistency (both sign-bit branches,
seeded deterministically — an IN-HOUSE RE-DERIVATION, not an external
anchor, since only the libsignal vector's own nonce could reproduce its
exact bytes and that nonce isn't published).

## Double Ratchet (Part 2, `ratchet.zig`)

- **Seeding from X3DH.** `SK` becomes the initial root key `RK`; `AD` is
  stored in the `State` and mixed into every message's AEAD associated
  data. Bob's INITIAL ratchet keypair is his signed-prekey keypair (the
  standard Signal binding — the DH key Alice already mixed into X3DH), so
  `initAlice(sk, ad, bob_spk_pub, io)` and
  `initBob(sk, ad, bob_spk_keypair)` land on the same first chain purely by
  X25519 DH commutativity, exactly as X3DH's own two sides do.
- **KDF instantiation** (spec §5.2 leaves these application-defined):
  - `KDF_RK(RK, dh_out)` = HKDF-SHA256, `salt = RK`, `ikm = dh_out`,
    `info = ratchet.kdf_rk_info`, 64-byte output split `RK' ‖ CK`.
  - `KDF_CK(CK)` = HMAC-SHA256 keyed by `CK`, `HMAC(CK, 0x01) -> MK`,
    `HMAC(CK, 0x02) -> CK'` (the spec's exact recommended constants).
- **AEAD = ChaCha20-Poly1305**, NOT the spec's own AES-256-CBC+HMAC-SHA256
  example. The spec explicitly permits "an AEAD encryption scheme"; a real
  AEAD is simpler and less error-prone than hand-rolled encrypt-then-MAC,
  and ChaCha20-Poly1305's 32-byte key lines up with `MK`. The per-message
  key+nonce are `HKDF-Expand(MK, ratchet.aead_info)` (44 bytes → 32-byte
  key + 12-byte nonce), so `MK` is never a raw cipher key. Nonce reuse is
  structurally impossible: each `MK` is derived once and used for exactly
  one message. AEAD associated data = `AD ‖ header.toBytes()` (spec §3.4),
  binding the ciphertext to the sender's ratchet key + `PN`/`N` counters.
- **Transactional `decrypt` (fail-closed).** Unlike the spec's reference
  pseudocode, which mutates state as it goes, `decrypt` computes the whole
  ratchet advance (skip-then-DH-ratchet-then-skip, generating any new DH
  keypair) on a WORKING COPY plus a pending list of skipped keys, and
  commits to the real `State` ONLY after the AEAD tag verifies. A
  tampered/forged message therefore never advances, corrupts, or DoS-grows
  the session — it returns `error.MessageAuthenticationFailed` (or a parse/
  skip error) with `State` byte-for-byte unchanged.
- **`MAX_SKIP` / store bound (DoS, spec §6).** `max_skip` (1000) caps keys
  skipped in one chain per `decrypt`; a header claiming a message number
  further ahead is rejected (`error.TooManySkippedMessages`) BEFORE any
  `KDF_CK` or allocation, so a forged giant `N` cannot burn CPU or OOM.
  `max_skip_store` (2000) bounds total retained skipped keys; growth past
  it is refused rather than silently evicted.
- **Forward secrecy + post-compromise security.** Chain keys advance
  one-way via `KDF_CK`; each message key is single-use and `secureZero`'d
  immediately after the AEAD call (forward secrecy). Every DH ratchet
  folds fresh X25519 entropy into `RK` via `KDF_RK`, so a session heals
  one full round-trip after a state compromise (post-compromise security).
- **Const-time / zeroization.** All secret-material operations use std's
  constant-time-on-secrets primitives (`X25519.scalarmult`, HMAC/HKDF over
  SHA-256, ChaCha20-Poly1305). `State.deinit` `secureZero`s the root key,
  both chain keys, the local DH secret key, and every stored message key;
  the transactional working copy is `secureZero`'d on every exit; consumed
  skipped keys are zeroed on removal. Known limitation: std's `HashMap`
  does not expose slot-zeroing, so a removed entry's backing bytes persist
  in the map's buffer until it is reused or freed (the whole buffer's live
  values are zeroed at `deinit`).
- **`decrypt` errors** are a tight set — `MessageAuthenticationFailed`
  (tamper/truncation), `TooManySkippedMessages` (DoS cap),
  `MessageKeyNotAvailable` (replay of a consumed in-order message, or a
  message before its chain exists), `KeyAgreementFailed` (pathological
  low-order ratchet key), plus `Allocator.Error`.
- **Out of scope**: header encryption (spec §4 — headers here are
  cleartext, so the ratchet public key + counters are observable), PQXDH
  seeding, and a stability-committed session-persistence byte format
  (`State` is an in-memory value only).

## Verification

- `zig build test-signal`: **all pass**, Debug AND
  `-Doptimize=ReleaseFast`, zero panics. `zig fmt --check
  modules/signal/` clean.
- Double Ratchet coverage: full interleaved Alice<->Bob session seeded
  from a live `x3dh.initiateUnverified`/`respond`, forcing repeated DH
  ratchets, every message round-tripping; out-of-order delivery within a
  chain AND across a DH-ratchet boundary (skipped-key store drains back to
  empty); `MAX_SKIP` giant-`N` rejection with state untouched and no OOM;
  tamper battery (flipped ciphertext / wrong `AD` / truncated buffer all
  fail closed, genuine message still decrypts afterward); replay of a
  consumed in-order message rejected; header codec round-trip + wrong-
  length rejection; `KDF_CK` 0x01/0x02 constant distinctness. No numeric
  reference vector exists (see below), so this is self-consistency +
  spec-adherence — the same footing as Part 1's X3DH agreement.

### Test-vector honesty (Double Ratchet)

The Double Ratchet specification, like X3DH and XEdDSA, publishes **no
numeric worked example**. Nor is there an off-the-shelf byte-exact KAT for
a clean spec-adherent instantiation: the reference implementations that DO
ship deterministic ratchet vectors (matrix's Olm/vodozemac; libsignal) use
their OWN protocol-specific instantiations — different AEAD (AES-CBC+HMAC),
different KDF `info` strings, Olm-specific chain/root derivations — so a
byte-exact cross-check would require re-implementing THEIR protocol, not
the Signal Double Ratchet spec's own composition. This module therefore
verifies by self-consistency (Alice's and Bob's independently-advanced
ratchets must agree on every message key across many DH ratchets — a
property that fails loudly on almost any construction bug) plus direct
adherence to the spec's stated KDF constants and algorithm, exactly as
Part 1's agreement is verified. The AEAD/KDF choice is documented above so
a caller who needs libsignal/Olm wire-compatibility knows it is NOT
provided.
- Coverage highlights: sign->verify round-trip; tampered message /
  tampered signature / malformed-key-and-signature fail-closed battery;
  sign-0 convention agreement (`verify`'s recovered `A` == `sign`'s
  forced `A`, both natural-sign branches exercised); libsignal
  known-answer vector — EXTERNAL ANCHOR — accepted byte-exactly (all 64
  single-byte tampers rejected) by the shipped `xeddsa.libsignal.verify`,
  rejected by the spec-pure `verify`, self-round-tripped under both
  `xeddsa.sign` and `xeddsa.libsignal.sign` over the vector's own sign-1
  key (nonce differs from libsignal's, so these round-trips are IN-HOUSE
  RE-DERIVATION, not a byte-exact reproduction of the vector's signature);
  `libsignal.sign`/`verify` self-consistency across both sign-bit branches
  (`xeddsa.zig`'s own in-file tests); std-Ed25519 cross-verification;
  X3DH `generateSignedPreKey` -> `initiate` -> `respond` end-to-end plus
  tampered-signature / substituted-prekey fail-closed cases.

## Anchoring

**Anchor grade:** class B · oracle MIXED

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** X3DH agreement+codec only self round-trip; XEdDSA has libsignal KAT (kat_test.zig)

**How it got there.** No external oracle exists for what remains. Signal publishes no official X3DH KAT; own Python oracle would be REDERIVED
