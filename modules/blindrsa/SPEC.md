# blindrsa — SPEC

RSA Blind Signatures (RFC 9474, "RSABSSA") over the sibling `rsa` module;
see [README.md](README.md) for purpose and API. Provenance: see
[NOTICE](NOTICE).

**Status: extract (complete).** All four RFC 9474 §4 operations
(`blind`/`blindWithFactor`, `blindSign`, `finalize`, `verify`) plus
`pssEncode` and `prepareIdentity`/`prepareRandomize` are implemented and
validated byte-exact against RFC 9474 Appendix A.1 and A.4 — including
`blind` itself, via the `blindWithFactor` deterministic seam fed the
RFC's own fixed blinding factor (`kat_vectors.zig`'s `r`). See "Resolved
design decisions" below for how the former "TODO(fable)" items landed.

## Design

- **Source of truth**: RFC 9474 §4 (the Blind/BlindSign/Finalize/Verify
  algorithms) and §5 (the RSABSSA variant table — hash, salt length,
  message-preparation function). `jedisct1/zig-blind-rsa-signatures` (MIT)
  was read as a structural design reference for how a Zig API around this
  RFC tends to shape its client/server split and `Context`-style blinding
  state — see `NOTICE` for what specifically was and wasn't consulted.
- **Layered on `rsa`, not `std.crypto.ff` directly**: every RSA
  primitive this module needs already exists in the sibling `rsa` module
  (`rsaep`/`rsavp1`/`rsadp`/`rsadpCrt`/`rsasp1`, `verifyPss`,
  `SecretKey`/`PublicKey` parsing, `generate`). `blindrsa` adds ONLY the
  blind-signature-specific layer: the blinding/unblinding transform and
  the RFC 9474 protocol sequencing. This mirrors the `jwe`/`opcua`/`x509`/
  `dnssec` pattern of thin RSA-consumer modules built on `rsa`, not a
  parallel RSA implementation.
- **`pssEncode` delegates to `rsa`** (see also `root.zig`'s module doc
  comment): `rsa`'s EMSA-PSS-ENCODE (`emsaPssEncode`, which internally
  also owns MGF1) is now `pub`, exported specifically because RFC 9474's
  Blind needs the ENCODED INTEGER on its own — the RSA private-key
  operation happens later, server-side, over the BLINDED integer, in
  `blindSign` — unlike `rsa.signPss`, which always follows encoding
  immediately with RSASP1. `pssEncode` here is a thin wrapper over
  `rsa.emsaPssEncode`, kept as its own public name (not a bare re-export)
  because it is this module's documented entry point for that standalone
  step. No local MGF1 copy remains. Validated byte-exact against RFC
  9474's own vectors (`kat_test.zig`).
- **`Context`** bundles exactly what `finalize` needs that `blind` alone
  produces: `r_inv` (the blinding inverse), `prepared_msg` (borrowed,
  for the trailing `verify` call), and `salt_len`. It deliberately does
  NOT store the salt bytes themselves — `verify`/`rsa.verifyPss` only
  need `salt_len` to know how many trailing bytes of the recovered EMSA
  encoding to treat as salt; the actual salt value is recovered from the
  signature during verification, not supplied by the caller.
- **`blindSign` composes from already-public `rsa` primitives**: RFC
  9474's BlindSign is `rsa.rsasp1` (sign the opaque blinded integer, CRT
  fast path) plus `rsa.rsavp1` (the mandatory self-check), wrapped in RFC
  9474 §7.2's RECOMMENDED private-op blinding — see "Resolved design
  decisions" item 3.
- **Fixed-width primitive calls**: `rsa.rsasp1`/`rsa.rsavp1` take a
  `comptime` modulus length; `blindrsa`'s modulus length is runtime.
  Every call is made at `rsa.max_modulus_len` width with the operand
  zero-left-padded — OS2IP is zero-padding-invariant and I2OSP output is
  re-sliced to the real `modulus_len`, so one instantiation serves every
  key size.

## RSABSSA variants (RFC 9474 §5)

| Variant | salt_len | Prepare | Wired KAT |
|---|---:|---|---|
| RSABSSA-SHA384-PSS-Randomized (RECOMMENDED) | 48 | `prepareRandomize` | Appendix A.1 |
| RSABSSA-SHA384-PSSZERO-Randomized (RECOMMENDED) | 0 | `prepareRandomize` | not yet wired |
| RSABSSA-SHA384-PSS-Deterministic | 48 | `prepareIdentity` | not yet wired |
| RSABSSA-SHA384-PSSZERO-Deterministic | 0 | `prepareIdentity` | Appendix A.4 |

All four variants mandate SHA-384 for both the message hash and MGF1 —
this module takes `Hash` as a `comptime` parameter (matching `rsa.signPss`/
`rsa.verifyPss`'s own convention) rather than hardcoding it, so a caller
technically CAN pass a different hash; RFC 9474 compliance requires
`Sha384`. Appendix A.2 (PSSZERO-Randomized) and A.3 (PSS-Deterministic)
share the SAME 4096-bit key as A.1/A.4 (already in `kat_vectors.zig`) and
are straightforward to add — only their `msg`-dependent fields
(`encoded_msg`/`blinded_msg`/`blind_sig`/`sig`, and A.2's `msg_prefix`)
are new transcription, not new design.

## Resolved design decisions (the former "TODO(fable)" items)

1. **The composite-modulus inverse** — needs extended Euclid over
   `std.math.big.int.Managed` (`std.crypto.ff` has no `invert`, and Fermat
   inversion needs a prime modulus). `rsa` needed the identical routine
   for its own key derivation and now exports it as `pub fn
   bigModInverse` (`modules/rsa/src/root.zig`); this module calls that
   directly (via `feInvert`) instead of carrying a local copy — the only
   code that remains here is the byte<->BigInt glue (`newBig`/
   `bigFromBytes`, still needed for `isCoprime`'s own gcd check) and the
   masking layer (`maskedInvert`) around the call. Validated against
   RFC-published data: inverting the RFC's `r` reproduces the RFC's
   published `inv` byte-exact over the real 4096-bit composite `n` (plus
   small hand-checkable cases and gcd≠1 rejection).
   **Timing posture**: `rsa.bigModInverse`'s Euclid loop is variable-time
   in its operands (same contract in both modules — verified before
   unifying: `rsa` and `blindrsa`'s prior local copies were the same
   bare, unmasked algorithm; the masking is layered on top by the caller
   in both cases — `rsa`'s own `invModN` masks by only ever calling it on
   a fresh random `r`, `blindrsa`'s `maskedInvert` masks explicitly), so
   secret inputs never reach it raw — see "Constant-time" under "Threat
   model" below for the masking construction.
2. **`blind`** — implemented per the RFC construction (gcd(m,n) check via
   `big.int.gcd`, rejection-sampled uniform `r ∈ [1,n)`, masked inverse,
   `x = RSAVP1(pk,r)` via `rsa.rsavp1`, `blinded_msg = m·x mod n` via
   constant-time `ff.mul`). A second entry point, **`blindWithFactor`**,
   takes a caller-supplied `r` — the KAT-mode seam that makes `blind`'s
   output byte-exactly reproducible against Appendix A (the RFC pins
   `inv` but not `r`; `kat_vectors.zig` embeds the recomputed
   `r = inv⁻¹ mod n`, cross-checked in Python both ways before
   embedding). `blindWithFactor` runs the inverse UNMASKED (deterministic
   by design) — documented as test/KAT-grade, production callers use
   `blind`.
3. **`blindSign`** — RFC 9474 §7.2's private-op-blinding hardening is
   IMPLEMENTED (not skipped, not inherited — `rsa.rsasp1` does no message
   blinding of its own): a fresh secret `b ∈ [1,n)` is drawn per call,
   the CRT private-key operation runs on `m·b^e mod n` instead of `m`,
   and the result is unblinded with `b⁻¹` (via the masked inverse). The
   output is bit-identical to the unblinded computation (asserted by the
   byte-exact Appendix A KATs under two different RNG seeds), so this
   costs one extra public-exp modexp + two muls per signature and changes
   no observable behavior. `blindSign` therefore takes a
   `random: std.Random` parameter; the mandatory RSAVP1 self-check
   remains fail-closed on top.
4. **`finalize`** — implemented: `s = z · ctx.r_inv mod n` (constant-time
   `ff.mul`), I2OSP, then the MANDATORY trailing `verify` — the only
   return path goes through it, and a non-canonical `blind_sig`
   (`z >= n`) fails closed with the same terminal
   `error.SignatureVerificationFailed` (no separate error oracle).

## Uniform sampling of `r ∈ [1, n)`

Filling `Modulus.bits()` random bits and reducing mod `n` (the "reduce a
wide random value" pattern `rsa` itself uses in `generatePrime`/
`reduceWide` for OTHER purposes) is subtly WRONG here: it is biased
whenever `n` is not a power of two — which an RSA modulus never is — with
the bias concentrated on the LOW end of `[0, n)` (values just above a
multiple of `2^bits(n)` wrapping in the reduction get hit more than once).
For most uses in this repository that bias is immaterial (e.g. reducing a
hash output into a scalar field for a nonce), but `r`'s DISTRIBUTION is
exactly what the blinding security proof leans on (a non-uniform `r`
leaks information about `m` through `blinded_msg`'s distribution).
`blind` step 5 (`sampleFe` in `root.zig`) therefore uses REJECTION
sampling: draw `bits(n)` random bits (top byte masked, so acceptance
probability exceeds 1/2 per draw), interpret big-endian, reject and
redraw if the result is `>= n` or `== 0` — the same
constant-`ish`-effort reject-sample shape `rsa.generate`/`generatePrime`
already use elsewhere in this repository for prime candidates, just with
a different accept predicate (`< n`, not primality). The same sampler
feeds `blindSign`'s §7.2 blinding factor and `maskedInvert`'s masks.

## Threat model / limits

- **Blindness relies on `r`'s secrecy and uniformity.** `r` (and its
  inverse, stored in `Context.r_inv`) must never be reused across
  `blind` calls, must be drawn from a cryptographically secure RNG, and
  must be uniform over `[1, n)` (see "Uniform sampling" above) — a biased
  or reused `r` degrades or breaks the unlinkability property that is
  this scheme's entire point (a signer who can correlate two
  `blinded_msg`s sharing structure in `r` can potentially link the
  eventual `sig` back to the signing session).
- **One-more-unforgeability rests on RSA**, specifically the "one-more-RSA-
  inversion" assumption RFC 9474 §7.1 cites — this module (and `rsa`
  beneath it) do not independently strengthen that; a signer's key
  strength is exactly `rsa`'s own guidance (RFC 8017-conformant modulus
  sizes, `rsa.generate`'s FIPS 186-5-style constraints).
- **`blindSign`'s mandatory self-check is fail-closed by design**: like
  the sibling `adaptor` module's `preSign`, a correct implementation must
  NEVER return a `blind_sig` that fails its own `RSAVP1` self-check —
  this defends against fault-injection/bit-flip attacks on the CRT
  private-key operation (the classic Boneh-DeMillo-Lipton RSA-CRT fault
  attack; a single corrupted CRT half can otherwise leak the private key
  through the faulty signature). RFC 9474 §7.2's additionally-recommended
  private-op blinding IS implemented on top — see "Resolved design
  decisions" item 3.
- **`finalize`'s trailing `verify` is mandatory, not optional** — the
  entire point of Finalize double-checking its own unblinded output is
  that a malicious or faulty signer's `blind_sig` must never be handed
  back to the caller unverified; this is already enforced structurally
  (the ONLY way `finalize` can return a `sig` is through the real
  `verify` wrapper — see `root.zig`'s doc comment for the exact call it
  must make).
- **Constant-time posture (as implemented)**: every modular
  multiplication and exponentiation on secret material goes through
  `std.crypto.ff`'s constant-time paths — the private-key operation
  inside `blindSign` is `rsa.rsasp1`'s CRT modexp (constant-time `pow`),
  and every secret-operand `mul` (blinding, unblinding, unmasking) is
  `ff`'s constant-time multiplication. The ONE inherently
  non-constant-time piece is the extended-Euclid modular inverse
  (`big.int` division loop — `ff` cannot express a composite-modulus
  inverse, and Bernstein-Yang-style constant-time inversion was judged
  out of scope). The secret paths therefore never feed a raw secret into
  it: `blind` and `blindSign` invert through `maskedInvert`, which runs
  Euclid on `v = x·u mod n` for a fresh uniform secret mask `u` — a
  value statistically independent of `x` — and unmasks with one more
  constant-time `mul` (`x⁻¹ = v⁻¹·u`). Only the deterministic
  `blindWithFactor` KAT seam inverts its input directly (documented on
  the function; production clients use `blind`). Secret byte buffers
  (`r`, `x = r^e`, `b`, Euclid scratch arenas) are wiped with
  `std.crypto.secureZero` on scope exit. Exponentiation by the PUBLIC
  `e` uses `rsa.rsavp1`'s `powPublic` (variable-time in `e` only —
  constant-time with respect to the secret base, per `ff`'s contract).
  `verify`/`pssEncode` handle only PUBLIC data (mirrors
  `rsa.verifyPss`'s own "not required" note).
- **This module enforces no rate limiting / token redemption-uniqueness
  policy** — an anonymous-token deployment (e.g. Privacy Pass) built on
  top of `blindrsa` must track spent tokens / apply its own issuance
  policy; that is out of scope here, same as `jwt`/`jwe` not tracking
  token replay.

## Verification

- `zig build test-blindrsa` — pass, Debug AND
  `-Doptimize=ReleaseFast`, zero panics. `zig fmt` clean.
- Byte-exact KATs against RFC 9474 Appendix A.1 (PSS-Randomized) and A.4
  (PSSZERO-Deterministic): `pssEncode` → `encoded_msg`;
  `blindWithFactor` (fed the RFC's fixed `r`) → `blinded_msg` AND
  `ctx.r_inv` == the RFC's published `inv` (this pair independently
  validates the local extended-Euclid inverse against RFC data);
  `blindSign` → `blind_sig` (asserted under two different RNG seeds —
  proves the §7.2 internal blinding is output-invariant); `finalize` →
  `sig`; `verify` accepts both published `sig`s.
- Fail-closed reject coverage: tampered `blind_sig` (either end),
  wrong-length `blind_sig`, mismatched `Context` (wrong message, wrong
  `salt_len`, corrupted `r_inv`), tampered/wrong-message/wrong-salt-len
  plain `verify`, out-of-range or wrong-length `blinded_msg` at
  `blindSign`, and bad blinding factors at `blindWithFactor` (zero,
  `>= n`, and `r = p` — a real factor of `n`, the gcd≠1 path).
- Private-helper unit tests in `root.zig`: `rsa.bigModInverse` via `feInvert`
  (small hand-checkable case, non-coprime rejection, RFC `r` ↔ `inv`
  round-trip over the real 4096-bit composite, factor-of-`n` rejection),
  `maskedInvert` (mask cancels exactly; rejects non-invertible input),
  `isCoprime` (factors of `n`, RFC `encoded_msg`s, 0 and 1), and
  `sampleFe` (always in `[1, m)` for a modulus exercising the top-byte
  mask).
- Random-path round-trips: `blind → blindSign → finalize → verify` over
  the RFC 4096-bit key (both PSS and PSSZERO salt lengths, asserting a
  fresh `r` does NOT reproduce the KAT `blinded_msg`) and over a fresh
  `rsa.generate(1024)` keypair, including same-session tamper rejection.
- To re-derive/re-check `kat_vectors.zig`'s recomputed `r` in Python:
  `r = pow(inv, -1, n)`, then assert `r * inv % n == 1` and
  `blinded_msg == encoded_msg * pow(r, e, n) % n` for both A.1 and A.4.

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** RFC 9474 Appendix A.1/A.4 byte-exact KATs
