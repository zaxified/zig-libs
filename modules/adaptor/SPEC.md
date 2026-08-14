# adaptor — SPEC

Schnorr adaptor signatures ("one-time verifiably encrypted signatures",
the scriptless-scripts construction) over BIP340 on secp256k1; see
[README.md](README.md) for purpose and API. Provenance: see
[NOTICE](NOTICE).

**Status: complete.** Wire codecs (`AdaptorPoint`, `PreSignature`) and the
four crypto cores (`preSign`, `preVerify`, `adapt`, `extract`) are all
implemented — no `@panic`/TODO stub remains in `root.zig`. See "The four
crypto cores" below for what each does and how it is anchored.

## Design

- **Source of truth**: no BIP or formal spec exists for this scheme (see
  `NOTICE`) — the construction here is assembled from the public
  scriptless-scripts literature and cross-validated against secp256kfun's
  `schnorr_fun::adaptor` Rust module (a design reference, not ported
  source). The curve group is `std.crypto.ecc.Secp256k1` (same as
  `bip340`); tagged hashing, x-only key/signature handling, and — the
  scheme's headline property — the FINAL challenge tag are all reused
  from the sibling `bip340` module rather than re-derived.
- **The four algorithms** (standard scriptless-scripts terminology,
  cross-referenced against secp256kfun's differently-named equivalents in
  parens):
  - `preSign` (secp256kfun: `encrypted_sign`) — presigner produces a
    *pre-signature* bound to a public adaptor point `T = t·G`, without
    knowing `t`.
  - `preVerify` (secp256kfun: `verify_encrypted_signature`) — anyone can
    check a pre-signature is well-formed for `(pubkey, msg, T)`, again
    without knowing `t`.
  - `adapt` (secp256kfun: `decrypt_signature`) — whoever knows `t`
    completes the pre-signature into an ordinary 64-byte BIP340 signature.
  - `extract` (secp256kfun: `recover_decryption_key`) — whoever holds
    BOTH the pre-signature and the completed signature recovers `t`. This
    is the scheme's deliberate, one-time key-leaking property: adapting
    *is* revealing `t` to anyone who already had the pre-signature.
- **`AdaptorPoint`** (33-byte SEC1-compressed, `root.zig`): a GENERAL
  secp256k1 point, unlike `bip340.XOnlyPublicKey` — `T`'s y-parity is
  whatever the counterparty's choice of `t` happens to produce, with no
  BIP340-style even-y normalization applied to it. This is a real
  divergence from `bip340`/`musig2`'s x-only convention and is the root
  cause of the whole `needs_negation` bookkeeping below: BIP340 forces the
  FINAL signature's nonce point to have even y, but `T` is not under the
  presigner's control, so `R + T`'s parity is essentially a coin flip the
  presigner cannot influence except by choosing their own local nonce `R`
  — which they do (the entire `k0`/`needs_negation` dance in `preSign`).
- **`PreSignature`** (65 bytes: 32-byte x-only `r` ‖ 32-byte `s_prime` ‖
  1-byte `needs_negation` flag): unlike a plain `bip340.Signature` (64
  bytes, no flag), an adaptor pre-signature MUST carry the
  `needs_negation` bit explicitly — see the "Parity" section below for
  why it cannot be recomputed by a verifier.
- **Domain tags** (`aux_tag = "adaptor/aux"`, `nonce_tag =
  "adaptor/nonce"`, both routed through `bip340.taggedHash`/`bip340.hash.
  taggedHasher`): project-local names, since no BIP numbers this scheme
  (contrast `bip340`'s `"BIP0340/..."` tags and `musig2`'s `"MuSig/..."`
  tags, both drawn from their respective BIPs). The FINAL challenge hash
  is the one exception — it reuses `bip340.hash.challenge_tag` directly,
  unchanged, by design (see "The headline property" below).
- **Nonce derivation folds in `T`**: `preSign`'s nonce preimage is
  `t_pad || px || bytes(T) || msg` (`bytes(T)` = the 33-byte compressed
  adaptor point) — NOT just `t_pad || px || msg` as plain `bip340.sign`
  uses. This binds the nonce to the specific `T` a pre-signature is being
  produced for, so presigning the same message under two different
  adaptor points can never reuse a nonce (mirrors secp256kfun's
  `derive_nonce!` macro, which includes its own `Y` in the public nonce
  preimage for the identical reason).

## The headline property: `adapt`'s output is a PLAIN BIP340 signature

The single design choice that makes this scheme composable with
everything else in this repository: `preSign`'s challenge hash reuses
`bip340.hash.challenge_tag` UNCHANGED, and `adapt` never touches the `r`
half of the pre-signature. The result is that `adapt(presig, t)`'s 64-byte
output is — byte for byte — exactly what `bip340.sign` would have
produced had the signer simply signed with an effective nonce `k + t` (for
the appropriate sign of `t`) from the start. `bip340.verify` accepts it
with zero awareness that an adaptor scheme was involved. `kat_test.zig`'s
"full pipeline" test asserts this directly, which — because `bip340`
itself is byte-exact against all 19 official BIP340 vectors — makes
`bip340.verify` the STRONGEST available oracle for the `adapt`/`preVerify`
half of this module, in the total absence of any official adaptor-sig test
vectors.

## Parity — the `needs_negation` bit (the single easiest bug to introduce)

This is this scheme's `musig2`-style "most common from-scratch mistake"
class (see `musig2/SPEC.md`'s own parity section for the sibling issue it
solves differently). The chain of reasoning:

1. BIP340 signatures always commit to a nonce point `R` with EVEN y (the
   `lift_x` convention) — a 32-byte x-only encoding never carries a
   parity bit of its own; the even-y half of the pair is chosen by fiat.
2. An adaptor signature's REAL, final nonce point is `R_hat = k·G + T`
   (`k` = the presigner's local nonce scalar, `T` = the externally-given
   adaptor point). The presigner controls `k` but NOT `T` — so `R_hat`'s
   parity is effectively randomly determined by `T`, a value the
   presigner does not choose.
3. Therefore the presigner CANNOT simply "pick the nonce that gives even
   y" the way plain `bip340.sign`'s step 7 does (there, the presigner
   controls `R = k·G` entirely, so trying `k` vs `n-k` is enough). Instead:
   the presigner computes `R_hat = k0·G + T` for an arbitrary honestly-
   random `k0`, observes its ACTUAL parity, and:
   - if `R_hat` already has even y: use `k = k0` unchanged, encode
     `needs_negation = false`, and publish `r = x(R_hat)`.
   - if `R_hat` has odd y: use `k = n - k0` (negate the LOCAL nonce
     scalar only — `T` is left alone, since the presigner cannot
     negate a point they didn't choose), encode `needs_negation = true`,
     and STILL publish `r = x(R_hat)` (negating a point flips only its
     y-coordinate, so `x(R_hat)` is identical either way — only which
     `k` was actually used, and hence `s_prime`'s value, differs).
4. **Why `needs_negation` cannot be recomputed by a verifier**: given only
   the published `(r, T)`, a verifier can form two candidate points,
   `lift_x(r) + T` and `lift_x(r) - T` — both are perfectly valid curve
   points, and nothing about `r`/`T` alone says which one was the
   presigner's TRUE, pre-canonicalization `R_hat`. Only the presigner,
   who alone knows the local nonce `k0` (hence `R = k0·G`, hence which of
   `R_hat`/`-R_hat` genuinely equals `k0·G + T`), can determine this bit.
   It is therefore PUBLISHED as an explicit byte in `PreSignature`, not
   derived.
5. **`adapt`/`extract` mirror the SAME flag in opposite roles**: `adapt`
   negates the ADAPTOR SECRET (`t → n-t`) iff `needs_negation`, before
   adding it to `s_prime`; `extract` negates the RECOVERED SCALAR
   (`(s - s_prime) → n - (s - s_prime)`) iff `needs_negation`, before
   comparing it against `T`. These are algebraic inverses of each other
   BY CONSTRUCTION — getting either one's negation direction backwards
   (or applying it to the wrong operand — e.g. negating `s_prime` instead
   of `t` in `adapt`) does not crash; it silently produces a
   pre-signature/signature pair that is either non-adaptable or that
   `extract`s to the WRONG secret, exactly the kind of bug a byte-exact
   KAT (not just a "does it round-trip with itself" property test) is
   needed to catch — hence `kat_vectors.zig` pins `s_prime` byte-exactly,
   not merely "whatever this implementation happens to produce".
6. **Test coverage**: `kat_vectors.zig`'s six vectors include TWO with
   `needs_negation = true` (vectors 3, 5) and FOUR with `needs_negation =
   false` (vectors 0, 1, 2, 4) — both branches of this bookkeeping are
   exercised byte-exactly, not just "eventually hit by chance" the way a
   pure property-test harness without curated inputs might leave to luck.

## Threat model / limits

- **Nonce derivation determinism + aux-rand**: identical rationale to
  `bip340`'s own SPEC.md — `aux_rand` is defense-in-depth against
  side-channel/fault-injection, not a secrecy requirement; a broken/reused
  nonce leaks the SIGNING key `d` via the standard Schnorr two-signatures
  algebra (this module's `preSign` mandates a self-verify before
  returning, same fail-closed philosophy as `bip340.sign`/`musig2.sign`).
- **Adaptor-secret leakage is BY DESIGN, not a bug**: unlike a signing
  key, the whole POINT of this scheme is that `t` becomes recoverable
  (via `extract`) to anyone who has BOTH the pre-signature and the
  adapted signature. A consumer must never treat `t` as if it stays
  secret once `adapt`'s output is published — that is the mechanism, not
  a leak (e.g. in a PTLC, this is exactly how the payment preimage
  propagates back through a Lightning route).
- **`T` must be a point the presigner does not control the discrete log
  of** (or, symmetrically, if they do, `preSign` is signing away nothing
  — the presigner could `adapt` their own pre-signature immediately).
  This module has no way to enforce that property; it is a PROTOCOL-level
  concern for whatever builds on `adaptor` (e.g. a PTLC construction must
  ensure `T`'s discrete log is the value that actually needs to flow
  through the route, not something the presigner already knows).
- **Constant-time**: `preVerify` handles only PUBLIC data (mirrors
  `bip340.verify`'s own "not required" note) — the variable-time
  `mulDoubleBasePublic` is appropriate there. `preSign`/`adapt` DO handle
  secret data (the presigner's local nonce `k`/`k0` in `preSign`; the
  adaptor secret `t` in `adapt`) and must use the same constant-time
  masked-select discipline `bip340.sign`'s step 7 / `musig2.sign`'s step
  1 already establish in this repository — never branch on the parity bit
  itself.
- **`extract`'s nonce-match check is required, not optional**: without
  the `full_sig.r == presig.r` check, `extract` would happily compute
  SOME scalar from `(s - s_prime)` even when `full_sig` has nothing to do
  with `presig` — the follow-up `implied.equivalent(T)` check catches
  most such cases, but the `r`-mismatch check fails fast and gives a
  clearer error (`error.NonceMismatch` vs `error.AdaptorSecretMismatch`).

## The four crypto cores (all implemented)

The four crypto cores in `root.zig` are all real — no `@panic`/TODO stub
remains. Each function's own doc comment in `root.zig` spells out the
exact construction step-by-step, following `bip340`'s own established
idioms (masked constant-time parity selects, `taggedHasher` streaming,
`mulDoubleBasePublic` for the public verify equation):

1. **`preSign`** — 9 steps (KeyPair normalization; aux-rand-masked nonce
   folding in `bytes(T)`; `R_hat = k0·G + T`; `needs_negation =
   has_odd_y(R_hat)`; constant-time masked `k` select; `e` via `bip340`'s
   own challenge tag; `s_prime = k + e·d`; mandatory `preVerify`
   self-check before returning).
2. **`preVerify`** — the two-sided equation (`s_prime·G - e·P` on one
   side; `lift_x(r) ± T`, sign per `needs_negation`, on the other) —
   never panics/errors in the real implementation, `false` on every
   failure path, mirroring `bip340.verify`.
3. **`adapt`** — negate `t` iff `needs_negation`, add to `s_prime`,
   concatenate with the unchanged `r`.
4. **`extract`** — check `r` match, subtract `s_prime` from `s`, negate
   iff `needs_negation`, verify the result's public point equals `T`.

Byte-exact oracle for all four: `kat_vectors.zig`'s six self-authored
vectors (see `NOTICE` for generation method), exercised by `kat_test.zig`.
The property-test layer (`preVerify` accept, `bip340.verify` accept,
`extract` round-trip, and the tamper-rejection cases) provides a SECOND,
independent correctness signal beyond the byte-exact numbers.

## Verification

- `zig build test-adaptor` and `-Doptimize=ReleaseFast` both go green;
  `zig fmt --check modules/adaptor/` clean.

## Anchoring

**Anchor grade:** class B · oracle REDERIVED

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle REDERIVED** — an in-house oracle re-deriving the answer by a different route. Catches implementation typos; does NOT catch a shared misreading of the spec.

**What the tests actually contain.** no official spec/vectors; kat_vectors.zig computed independently in Python (NOTICE)

**How it got there.** No external oracle exists for what remains. No schnorr adaptor vectors exist; DLC's ECDSA-adaptor.json is a different scheme
