# bip340 — SPEC

BIP340 Schnorr signatures over secp256k1; see [README.md](README.md) for
purpose and API. Provenance: see [NOTICE](NOTICE).

## Design

- **Source of truth**: BIP340 ("Schnorr Signatures for secp256k1",
  `bitcoin/bips`). The curve group itself (field/scalar arithmetic, point
  addition/doubling/scalar-mul, `lift_x`) is `std.crypto.ecc.Secp256k1` —
  BIP340 only adds the tagged-hash construction, the x-only/even-y
  convention, and the sign/verify equations on top.
- **std recon (confirmed against `lib/std/crypto/pcurves/secp256k1.zig`,
  0.16.0)**:
  - `Secp256k1.Fe` / `Secp256k1.scalar` (`Scalar.fromBytes` rejects
    non-canonical values ≥ the field/curve order — exactly BIP340's
    required range checks) give the field and scalar arithmetic.
  - `Secp256k1.recoverY(x: Fe, is_odd: bool) NotSquareError!Fe` **is**
    BIP340's `lift_x`: it recovers the y coordinate for a chosen parity,
    failing with `error.NotSquare` exactly when `x³+7` has no square root
    mod p (a public key/signature `r` that is "not on the curve"). This
    module always calls it with `is_odd = false` (BIP340's even-y
    convention).
  - `Secp256k1.fromAffineCoordinates` re-derives a point from `(x, y)`,
    re-checking the curve equation.
  - `Secp256k1.basePoint.mul(scalar_bytes, .big)` computes `d*G` (uses the
    comptime-precomputed base-point table — this is the fast path for
    public-key derivation and for the `s*G` half of verification).
  - **Verify's `s*G − e*P`**: `Secp256k1.mulDoubleBasePublic(p1, s1, p2,
    s2, endian) IdentityElementError!Secp256k1` computes `p1*s1 + p2*s2`
    *in variable time* (explicitly documented for signature verification
    use) — exactly the double-base multiply this module's `verify` needs.
    There is no separate point-subtraction-of-scalar-multiples helper, so
    verify must compute `R = mulDoubleBasePublic(Secp256k1.basePoint, s,
    P, scalar.neg(e_bytes, .big), .big)` (negate `e` mod n first, then add
    — not "multiply then subtract points"). `rejectIdentity`/the
    `IdentityElementError` this returns is exactly the "R is the point at
    infinity" failure case (test-vector indices 9/10).
  - `toCompressedSec1`/`fromSec1` exist for full SEC1 point encoding but
    are NOT used here — BIP340's x-only encoding is a distinct 32-byte
    format (SEC1-compressed is 33 bytes with a parity-selector prefix
    byte); this module's own `XOnlyPublicKey`/`Signature` codecs own that
    shape instead.
- **Tagged hashing** (`hash.zig`): `taggedHash(tag, msg) =
  SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`. Since `SHA256(tag)` is exactly
  32 bytes, the fixed prefix `SHA256(tag) ‖ SHA256(tag)` is exactly one
  64-byte SHA-256 block; the SHA-256 state after absorbing that one block
  (`s`/`buf_len`/`total_len` — plain, non-`pub` fields have no
  cross-file privacy in Zig, so a value-copy is a real snapshot, not a
  simulation) is precomputed once per tag at comptime and reused by every
  `taggedHash` call for that tag, which then only hashes `msg`.
  `taggedHashRuntime`/`taggedHasherRuntime` implement the same construction
  for a tag that is only known at runtime (no comptime midstate to cache —
  the tag hash is recomputed per call); `tag` is taken as a slice of parts
  so a tag built by concatenation (e.g. BOLT#12's `"LnNonce" ‖ first_tlv`)
  needs no intermediate allocation. Added for DRY: BOLT#12's `lninvoice`
  module had hand-rolled this exact construction because its tag varies per
  TLV stream.
- **x-only public key / `lift_x`** (`XOnlyPublicKey`): parse rejects a
  non-canonical x (`x ≥ p`, `Fe.fromBytes`'s built-in check) and an x with
  no valid y (`recoverY`'s `error.NotSquare`). `lift()` always resolves to
  the EVEN-y point (BIP340's fixed convention — there is no "requested
  parity" parameter at this layer, unlike raw `recoverY`).
- **`xonlyBytesOf`**: a purely structural helper (no on-curve validation)
  that strips the SEC1 parity-prefix byte from a 33-byte compressed point
  or passes an already-32-byte x-only value through unchanged. Added for
  DRY: `lninvoice`'s BOLT#12 module had a local copy of exactly this
  33-or-32-byte-length switch for its `invreq_payer_id`/`invoice_node_id`
  fields (both stored as 33-byte compressed points but verified x-only,
  since BIP340 forces even-y via `lift_x` regardless of the parity byte).
- **Key derivation** (`SecretKey`/`PublicKey`/`KeyPair`): `SecretKey.
  fromBytes` enforces `d ∈ [1, n−1]`. `KeyPair.fromSecretKey` computes `P =
  d*G` and applies BIP340's even-y normalization (`d ← n − d` if `P.y` is
  odd) — this is exactly "Default Signing" steps 1–3, hoisted out of `sign`
  itself (which calls it) so the normalization lives in one place instead
  of being re-derived by hand per signature. `PublicKey.fromSecretKey` is
  a thin wrapper returning only the x-only public key half.
- **Signature codec** (`Signature`): 64 bytes, `r (32) ‖ s (32)`. Parse
  enforces `r < p` (`Fe.fromBytes`) and `s < n` (`Scalar.fromBytes`) —
  and *only* that; it deliberately does NOT attempt `lift_x(r)` (that
  belongs to `verify`, which needs the point `R`, not just its validity).
  Test-vector index 11 depends on this split: its `r` is a canonical field
  element (parses fine) that simply is not a valid x-coordinate (fails
  only once `verify` tries to lift it).

## Threat model / limits

- **Nonce derivation determinism + aux-rand**: BIP340 signing derives its
  per-signature nonce `k` deterministically from `(d, aux_rand, msg)` via
  `taggedHash("BIP0340/nonce", ...)`. `aux_rand` exists purely as
  side-channel/fault-injection defense-in-depth (RFC 6979-style
  determinism would otherwise make `k` a pure function of the secret key
  and message, which is safe against nonce-reuse but not against certain
  physical attacks) — it does NOT need to be secret or authenticated, only
  unpredictable to an attacker at signing time. A wrong or reused `k`
  (e.g. a broken RNG feeding `aux_rand`, or a nonce-derivation bug) leaks
  `d` from two signatures via the standard Schnorr nonce-reuse algebra —
  this is the single highest-severity property `sign`'s implementation
  must get right, which is exactly why BIP340 mandates the
  self-verification step before `sign` returns (catches a large class of
  such bugs, though not a broken RNG).
- **x-only / even-y convention**: every public key and every nonce point
  `R` is committed to the curve with an *implicit*, always-even y. This
  halves the search space per point (a real but small operational
  security consideration for adversarial pubkey generation) and is why
  `lift_x` — not full SEC1 point parsing — is the public-key/`R`-recovery
  primitive everywhere in this module.
- **r/s range + R.y-parity checks**: `verify` must reject `r ≥ p`, `s ≥
  n` (parse-level, already enforced by `Signature.fromBytes`/
  `XOnlyPublicKey.fromBytes` before `verify` is ever reached), and — the
  check most often gotten wrong in ad-hoc implementations — `R.y` odd
  after recomputing `R = s*G − e*P`. Skipping the parity check turns
  BIP340 verification into "any of two related signatures accepted",
  weakening the scheme's strong-unforgeability property. Test-vector index
  6 ("has_even_y(R) is false") exists specifically to catch this.
- **Constant-time**: NOT required for `verify`/`verifyBatch` (BIP340 §
  "Verification" explicitly notes this — all their inputs are public).
  `sign` DOES handle secret data (`d`, the derived nonce `k`) and should be
  written with the same care as any Schnorr/ECDSA signer (no secret-
  dependent branching/timing in the scalar arithmetic std already gives
  constant-time; the risk surface here is in code this module's `sign`
  itself adds around it, e.g. any early-return based on secret bits).
- **Batch verification's randomness**: the `a_2..a_u` coefficients
  (`verifyBatch`) must be drawn AFTER every `(pubkey, msg, sig)` triple in
  the batch is fixed, and must be unpredictable to whoever supplied the
  signatures — reusing/predicting them lets a forger craft a batch that
  passes despite containing an individually-invalid signature.

## TODO(fable) — done (crypto pass completed)

All three formerly-stubbed cores are implemented and KAT-validated
(byte-exact against all 19 official vectors, Debug + ReleaseFast):

1. **`sign`** — BIP340 "Default Signing", all 10 steps including the
   mandatory self-verify-before-return (fails closed with
   `error.SignatureVerificationFailed` instead of emitting a maybe-bad
   signature). Nonce/challenge hashes stream via `hash.taggedHasher`
   (the comptime tag midstate + `update` per part — no concatenation
   buffer). The step-7 `k ← n − k'` even-y normalization of the nonce is
   a constant-time masked byte select between the two candidate scalars
   (no branch on `R.y`'s parity, which is one bit derived from the
   secret nonce hash); all scalar arithmetic (`k + e·d mod n`) is
   `Secp256k1.scalar`'s constant-time field ops. `int(hash) mod n` is a
   REDUCING conversion (`Scalar.fromBytes48` over a zero-widened 48-byte
   value) — `Scalar.fromBytes` would reject instead of reduce.
2. **`verify`** — the `s*G − e*P` equation exactly as the recon note
   above prescribes: `mulDoubleBasePublic(basePoint, s, P, −e mod n,
   .big)`, then identity (vectors 9/10), `R.y` parity (vector 6), and
   `bytes(x(R)) == sig[0..32]` (vectors 7/8/11 — note 11 needs no
   explicit `lift_x(r)` in single verification: a computed `x(R)` can
   never byte-equal an r that is not a valid x-coordinate). Returns
   `false` on every failure path, never panics/errors, and re-runs the
   lift/range checks itself so it is safe on hand-constructed values.
3. **`verifyBatch`** — the random-linear-combination equation with `a_1
   = 1` and `a_2..a_u` drawn from `io.randomSecure` (std's
   `Scalar.random` loop inlined around the fail-closed draw: wide
   reduction, non-zero by rejection sampling) after the whole `items`
   slice is bound. The randomizers are a SOUNDNESS input — predictable
   `a_i` let an attacker pass a batch of individually-invalid signatures
   whose errors cancel — so an entropy failure returns `false` (batch not
   verified) rather than checking against a degraded draw. The RHS
   accumulates per item as one variable-time double-base multiply
   `a_i·R_i + (a_i·e_i)·P_i` plus a complete point addition (std's API
   tops out at two bases per multiply — same equation and acceptance
   set as a single 2u+1-term multi-scalar multiply, just less batching
   speedup; documented in the function's doc comment). A per-item
   identity result contributes nothing and is skipped; a zero LHS
   scalar (base `mul` reports identity) accepts iff the RHS is the
   identity too. Validated by cross-check against `verify` (all-valid
   batch accepts incl. the empty batch; corrupting any single
   signature/message/pubkey, or injecting vector 11's non-lifting `r`,
   rejects).

The two formerly-`error.SkipZigTest` KAT tests in `kat_test.zig` are
re-enabled, plus the new batch-correctness test. Design references: none
beyond the BIP340 specification text itself and `std.crypto.ecc.Secp256k1`
(see `NOTICE`).

## Verification

- KAT oracle: the official BIP340 test vectors, `bip-0340/
  test-vectors.csv` from `bitcoin/bips` (see `NOTICE` for the fetch
  source), embedded verbatim in `src/kat_vectors.zig` — 19 rows: 8 with a
  known secret key (indices 0–3, 15–18; the last four added 2022-12 to
  cover variable-length messages of size 0/1/17/100 bytes) and 11
  verify-only (indices 4–14; one must verify TRUE, ten must verify
  FALSE).
- Exercised (`src/kat_test.zig`): `XOnlyPublicKey.fromBytes`/`lift` on all
  19 public keys (2 must fail: index 5 not on the curve, index 14 exceeds
  the field size); `Signature.fromBytes`'s range checks on all 19
  signatures (2 must fail parse-level: index 12 `r == p`, index 13 `s ==
  n`; index 11 must NOT fail parse-level, only later at `verify`);
  `KeyPair`/`PublicKey` derivation from secret key on all 8 secret-key
  vectors, checked against the vector's published public key; full `sign`
  round-trip (each of the 8 secret-key vectors produces the exact 64
  published signature bytes — which transitively KATs the nonce
  derivation, both even-y normalizations, and the challenge hash); full
  `verify` accept/reject (all 19 rows match their `verification result`
  column exactly, including all 10 negative ones); `verifyBatch`
  cross-checked against `verify` (all-valid batch + empty batch accept;
  any single corrupted signature/message/pubkey, or a non-lifting `r`,
  rejects the whole batch).
- Both `zig build test-bip340` (Debug) and `-Doptimize=ReleaseFast` pass;
  no `error.SkipZigTest` remains in the module.
