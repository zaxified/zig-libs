# signal — SPEC (Part 1: X3DH + XEdDSA)

X3DH (signal.org/docs/specifications/x3dh) + XEdDSA
(signal.org/docs/specifications/xeddsa); see [README.md](README.md) for
purpose and API. Provenance: see [NOTICE](NOTICE).

**Status: Part 1 complete.** `x3dh.zig`'s DH+HKDF agreement, both wire
codecs, and `xeddsa.zig`'s `sign`/`verify` (with the Montgomery->Edwards
sign-0 recovery, `edwardsFromMontgomery`) are implemented and tested —
31/31 in Debug and ReleaseFast, including a libsignal known-answer
vector; see "Verification" below.

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
- **Spec variant, not deployed-libsignal variant** (`xeddsa.zig`'s module
  doc comment): the XEdDSA paper forces the signer's Edwards key to
  sign 0 and leaves `s` a canonical scalar; DEPLOYED libsignal (C, Java,
  and current Rust — its source says so explicitly) instead signs with
  the natural-sign key and smuggles the sign bit in `s`'s top bit. This
  module implements the PAPER. The two are wire-incompatible for the
  ~half of keys whose natural Edwards point has sign 1 — `kat_test.zig`
  pins the incompatibility (and validates the shared recovery math) with
  libsignal's own published test vector.

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
- **Constant-time**: `X25519.scalarmult`/`X25519.KeyPair.generate` are
  std's own constant-time-on-secret-material primitives (RFC 7748
  clamped Montgomery ladder) — this module performs no additional
  secret-dependent branching of its own in the DH/HKDF path.
  `xeddsa.sign` handles the secret scalar with `Edwards25519.scalar`'s
  constant-time ops, a constant-time `basePoint.mul`, and a BRANCHLESS
  masked select for the negate-if-sign-1 step (the sign bit itself is
  public-equivalent — it is a deterministic function of the public key
  pair `±A`, and deployed libsignal transmits it in every signature);
  secrets are `std.crypto.secureZero`d on exit. `xeddsa.verify` operates
  on public inputs only (variable-time `mulDoubleBasePublic`, like std's
  own Ed25519 verifier) and fails closed on every malformed input.
- **No replay/freshness protection is this module's job**: X3DH itself
  provides none beyond "OPK consumed once" (a server-side bookkeeping
  concern, not cryptographic); session continuity/replay protection is
  Part 2's (Double Ratchet's) responsibility.

## XEdDSA implementation notes

`xeddsa.zig` implements the spec's construction on std primitives only:

1. **`sign`** — Montgomery-seed -> sign-0-forced Edwards keypair
   (`calculateKeyPair`: clamp, reduce, `basePoint.mul`, branchless
   negate-if-sign-1); `hash1`-domain-separated nonce
   (`SHA-512(0xFE || 0xFF*31 || a || M || Z)`, wide-reduced mod L, over
   the possibly-negated scalar `a` per spec); `R = r·B`;
   plain-`SHA-512`-domain challenge `h = hash(R || A || M) mod L`;
   `s = r + h·a mod L` (`scalar.mulAdd`); return `R || s`.
2. **`verify`** — `edwardsFromMontgomery` recovers the sign-0 Edwards
   point `A` from the Montgomery `u`-coordinate alone (`y = (u-1)/(u+1)`
   via `Fe` ops, then `Edwards25519.fromBytes` with sign bit 0 picks the
   even-`x` root and rejects twist points), fail-closed on non-canonical
   `u` and the `u = p-1` pole; then `rejectIdentity`/`rejectLowOrder`,
   `scalar.rejectNonCanonical(s)`, and the standard Ed25519-shaped
   `sB - hA == R` cofactorless byte comparison
   (`Edwards25519.mulDoubleBasePublic`). Every failure path returns
   `false`; nothing panics on attacker input.

Test-vector status: the XEdDSA spec text publishes no numeric vector.
`src/kat_test.zig` embeds libsignal's own `test_curve25519_signature`
vector (numeric facts from libsignal-protocol-c's test suite; see
`NOTICE`) and exercises it two ways — a test-local verifier faithful to
DEPLOYED libsignal's sign-bit-in-`s` variant (built on this module's
`edwardsFromMontgomery`) must accept it byte-exactly with all 64
single-byte tampers rejected, and the module's spec-pure `verify` must
reject it (variant incompatibility, pinned). `sign` is additionally
cross-checked against `std.crypto.sign.Ed25519`'s independent verifier
(an XEdDSA challenge hash is byte-identical to Ed25519's, so a spec-pure
XEdDSA signature must verify as Ed25519 under the recovered sign-0 `A`).

## Verification

- `zig build test-signal`: **31/31 PASS**, Debug AND
  `-Doptimize=ReleaseFast`, zero panics. `zig fmt --check
  modules/signal/` clean.
- Disk-vs-running test count (CONVENTIONS.md §6 step 3):
  `grep -c '^\s*test ' modules/signal/src/*.zig` summed across files (31)
  equals `zig build test-signal --summary all`'s reported total (31).
- Coverage highlights: sign->verify round-trip; tampered message /
  tampered signature / malformed-key-and-signature fail-closed battery;
  sign-0 convention agreement (`verify`'s recovered `A` == `sign`'s
  forced `A`, both natural-sign branches exercised); libsignal
  known-answer vector (accept under the variant verifier, reject under
  spec-pure `verify`, round-trip under this module's own `sign` with the
  vector's sign-1 key); std-Ed25519 cross-verification; X3DH
  `generateSignedPreKey` -> `initiate` -> `respond` end-to-end plus
  tampered-signature / substituted-prekey fail-closed cases.
