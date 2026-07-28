# vdf — spec

Wesolowski Verifiable Delay Function over an RSA hidden-order group; see
[README.md](README.md) for purpose and API. Provenance: see [NOTICE](NOTICE).

**Status: COMPLETE.** `group.zig` (Z_N* wrapper + the RSA-2048 Factoring
Challenge modulus + element validation) and `vdf.zig`'s `eval`,
`hashToPrime`, `pow2Mod`, and `Proof`'s codec are real and tested — as are
the two irreducible cores `prove` and `verify` (green in Debug +
ReleaseFast). `gate.core_implemented = true`, so the completeness/soundness
tests that call `prove`/`verify` run (and pass). See "The Fable cores"
below.

## The construction

`eval(N, x, T) = x^(2^T) mod N`, computed as `T` sequential modular
squarings. The delay is real IF AND ONLY IF the party computing it does
not know `N`'s factorization — see "Trusted-setup caveat" below.

Wesolowski's proof (Wesolowski, "Efficient Verifiable Delay Functions",
IACR ePrint 2018/623, §3) makes checking `y` cheap:

1. `l = hashToPrime(N, x, y, T)` — a Fiat-Shamir challenge prime, derived
   deterministically from the public transcript so no interactive
   verifier round-trip is needed.
2. `prove`: `π = x^floor(2^T / l) mod N`.
3. `verify`: `r = 2^T mod l` (cheap — `O(log T)` operations mod the small
   prime `l`, independent of `T`'s magnitude); accept iff `π^l · x^r == y
   (mod N)`.

Correctness is a one-line algebraic identity (`2^T = q·l + r` implies
`π^l · x^r = x^(q·l+r) = x^(2^T) = y`). Soundness — a cheating prover
cannot forge a `π'` for a wrong `y'` — is the module's actual crux; see
"Honest tier assessment" below.

## Design

### Group (`group.zig`)

`std.crypto.ff.Modulus(2048)`/`.Fe` — the same constant-time finite-field
primitive the `rsa` module's `Modulus`/`Fe` alias, sized to 2048 bits (the
RSA-2048 Factoring Challenge modulus's exact bit length) rather than
`rsa`'s 4096-bit ceiling. No modular-exponentiation primitive is
reimplemented; `square`/`mul`/`toBytes` are thin wrappers, and
`elementFromBytes` adds the untrusted-input validation
(`Fe.fromBytes`'s own canonical check, plus an explicit zero check) that
`prove`/`verify` run for every wire-supplied `x`/`y`/`π`.

The RSA-2048 Factoring Challenge modulus (617 decimal digits / 2048 bits)
is embedded as a hex literal, decoded once per call via
`std.fmt.hexToBytes` — see [NOTICE](NOTICE) for its provenance and the
verification steps taken against transcription error (a real risk: two
different renderings of the source Wikipedia page, fetched independently
during development, disagreed with each other in a middle digit run — the
page's raw wikitext, fetched directly rather than through an AI-summarized
render, was used to resolve it, and the embedded constant is additionally
cross-checked against three independently-computed Python KAT vectors —
see "Verification" below).

### `eval` (REAL)

`y := x; repeat T times: y := y*y mod N`. Mechanical — the entire point is
that there is nothing cleverer to do here; a shortcut would defeat the
construction. `T: u64`, so `2^T` itself is never materialized as an
integer (`eval` never computes `2^T`, only performs `T` squarings) —
`hashToPrime`/`pow2Mod` are the only places `T`'s VALUE (not the exponent
`2^T`) is used arithmetically, and both do so cheaply (`T` as an 8-byte
hash input; `T` as a `u64` exponent in a `~log T`-round square-and-multiply
mod a 256-bit prime).

### `hashToPrime` (REAL) — and why determinism, not just correctness, is load-bearing

`l` is derived from `SHAKE256(domain || N_bytes || x_bytes || y_bytes ||
T_be64)`, squeezed to 32 bytes, then walked upward by 2 (only odd
candidates) until a `mr_rounds = 64`-round Miller-Rabin test accepts one.

The one design decision here that is NOT a straight port of this repo's
existing per-module Miller-Rabin helpers (`rsa`/`paillier`/
`threshold_ecdsa` each carry their own, all private/non-exported — see
`root.zig`'s `meta.deps` note): Miller-Rabin's witnesses are drawn
**deterministically** from a hash of the CANDIDATE, not from OS entropy
(`std.crypto.random`, as the three sibling modules correctly use for key
generation). This matters because `hashToPrime` must be a pure function of
its `(N, x, y, T)` binding — the prover and an independent verifier, on two
different machines with no shared state, must derive the byte-identical
`l`. If witnesses came from OS entropy, there is a (negligible but
nonzero, `~4^-rounds` per round) chance that a composite candidate is
accepted as "probably prime" by one machine's random witnesses and
rejected by another's — which would make an HONEST proof fail to verify:
a liveness bug, and specifically the kind that manifests as a rare,
hard-to-reproduce flake rather than a clean, always-reproducible failure.
Seeding the witness PRNG from `SHA-256(domain || candidate_bytes)` fixes
this: the witness sequence is still unpredictable to an adversary picking
the candidate (candidates come from the SHAKE256 derivation, not from
anything the prover chooses), but is perfectly reproducible for the same
candidate across machines and runs.

The binding MUST include `y` (the prover's claim), not just `(N, x, T)` —
see `verify`'s doc comment in `vdf.zig` and "Honest tier assessment" below
for why omitting `y` from the binding breaks soundness entirely.

### `pow2Mod` (REAL)

`2^t mod l` via ordinary square-and-multiply — the mechanical half of
`verify`'s check (step 3 above). Public base, public exponent, no
cryptographic judgment call; implemented and tested today so that
`verify`'s eventual implementation only has to wire the four steps
together rather than also getting this piece right.

### `Proof` (REAL)

A single Z_N* element `π`, `group.modulus_bytes` (256) bytes, plus a
trivial length-checked byte codec. `l` is never carried on the wire — both
sides recompute it via `hashToPrime`.

## The Fable cores (`prove` / `verify`)

Both are implemented in `vdf.zig` (each with a complete per-step
doc-comment contract):

- `prove`: the EFFICIENT/STREAMING quotient computation (not the naive
  `std.math.big.int` materialization of `floor(2^T/l)`) — `streamingQuotientPow`
  walks the same `T` squarings `eval` performs, maintaining a small running
  remainder mod `l` to emit one quotient BIT per step, and accumulates `π`
  via Horner's-rule evaluation from those bits as they are produced. See
  the function's doc comment in `vdf.zig` for the exact per-step update
  rules; the streaming result is cross-checked against a naive
  `std.math.big.int` reference in the test suite.
- `verify`: the 4-step check (validate elements, recompute `l`, compute `r`
  via `pow2Mod`, check `π^l · x^r == y`), returning `false` (not
  panicking/UB) for any malformed/out-of-range input. The `hashToPrime`
  binding includes `y` — the soundness crux (see "Honest tier assessment").

## Honest tier assessment

**`eval` and `hashToPrime` are mechanical, not Fable-hard** — recipe, not
research. `eval` is "call `square` in a loop." `hashToPrime` is "hash,
force two bits, Miller-Rabin, increment" — the ONE subtlety (deterministic
vs. OS-random witnesses, above) is a five-line difference from a pattern
already established three times elsewhere in this repo, not a novel
design problem.

**`prove`/`verify` ARE genuinely Fable-hard, but narrowly so** — not in
code volume (each is well under 100 lines) but in two specific judgment
calls that are easy to get subtly, silently wrong:

1. **The streaming-quotient trick in `prove`.** The NAIVE algorithm
   (materialize `2^T` and `floor(2^T/l)` via `std.math.big.int`) is
   actually the EASY one to get right — it is a direct transcription of
   the formula. The hard part is the module's own design constraint (no
   big-int dependency, bounded memory regardless of `T`): tracking the
   long-division remainder correctly IN LOCK-STEP with `eval`'s existing
   squaring loop, and getting the "emit a quotient bit, then fold it into
   `π` via Horner's rule" bookkeeping exactly right. An off-by-one in
   either the remainder-doubling step or the quotient-bit ordering
   produces a `π` that is silently wrong for every `T` above some small
   threshold — the kind of bug that makes the naive-vs-streaming
   cross-check in this module's own test suite (both computing the same `π`
   two different ways, across the `q=0`/`q=1` division boundaries)
   mandatory, not optional polish; that cross-check ships.
2. **`verify`'s exact relation, specifically what `hashToPrime` must
   bind.** The four algebraic steps are five lines of code once known.
   The judgment call is upstream of the code: `hashToPrime`'s binding MUST
   include `y` (the prover's claim), not just `(N, x, T)` (the
   PRE-COMPUTABLE public inputs). Binding only `(N, x, T)` would let a
   cheating prover compute `l` in advance (before committing to any `y`
   at all), then search for a `(y', π')` pair satisfying the check for
   that PRE-CHOSEN `l` — the entire Fiat-Shamir soundness argument
   (Wesolowski §3 Theorem 1) rests on `l` being chosen AFTER, and as a
   function of, the prover's claim. This is invisible in the code (both
   versions type-check and pass a naive smoke test), which is exactly why
   it belongs in a dedicated pass with the full soundness argument in
   view, not folded into scaffolding where "it compiles and the happy
   path works" would be mistaken for "it's correct." It was implemented in
   that dedicated pass, with `y` in the binding and the soundness rejects
   pinned by tests below.

Compare: `ethfrag`/`xdp-classifier` (cited as the "mostly mechanical, not
actually Fable-hard" precedent this task asked to watch for) turned out to
be recipe-following once the wire format was pinned down. `vdf`'s
`eval`/`hashToPrime` are exactly that kind of mechanical. `prove`/`verify`
are NOT — but the reason is narrow and precise (the two points above), not
"big-integer cryptography is inherently hard." A Fable pass that
internalizes those two points before writing code should produce a short,
correct implementation; one that treats this as "just implement the
formula" is the module's single biggest risk.

## Trusted-setup caveat

See [README.md](README.md)'s "Trusted-setup caveat" section for the
short version. In full: the VDF's entire security rests on nobody knowing
`N`'s factorization. Given `N = p·q`, `λ(N) = lcm(p-1, q-1)` collapses
`eval`'s `T` sequential squarings to a single cheap computation
(`x^(2^T mod λ(N)) mod N`, `O(log T)` operations instead of `O(T)`) — this
module's own `kat_test.zig` demonstrates exactly this shortcut, on a
factorization-KNOWN toy modulus, as an independent-formula cross-check of
`eval`'s correctness (see "Verification" below). The RSA-2048 Factoring
Challenge modulus is safe because it was a real, public, unclaimed
challenge (1991-2007) with a $200,000 prize for factoring it — no
plausible incentive exists for a factorization to be known and hidden.
A caller-supplied `N` has none of that provenance; using one safely
requires either trusting its generator or running a genuine multi-party
"RSA-UFO" modulus-generation ceremony that never reconstructs `p, q` in
one place. This module intentionally does not pick a group family that
sidesteps the caveat (a class group of negative fundamental discriminant
has provably unknown order with NO trusted setup — the construction
Chia and most production VDF deployments actually ship) — see "Non-goals
/ follow-ups" below.

## Verification

- **`eval`**: three byte-exact vectors against the RSA-2048 Factoring
  Challenge modulus (`x=5`, `T ∈ {1, 5, 1000}`), each independently
  computed via Python's arbitrary-precision `pow(x, 2**T, N)` — a
  cross-LANGUAGE check (CPython's own modexp, not this module's
  sequential-squaring loop). Additionally, a factorization-known toy
  modulus (`p=1000003, q=999983`, both verified prime) cross-checks
  `eval`'s sequential-squaring result against the Euler's-theorem shortcut
  described above, computed via an entirely separate code path — this is
  an independent FORMULA, not a second run of the same loop.
- **`hashToPrime`**: one byte-exact vector (the same `T=1000` `(N,x,y)`
  binding as the `eval` vectors above) against an independent Python
  re-implementation of the exact SHAKE256-candidate + increment-by-2 +
  Miller-Rabin search (found the same prime after the same 27
  increments), plus determinism (same binding -> same `l`, checked twice)
  and sensitivity (changing any one of `N`/`x`/`y`/`T` changes `l`) tests,
  plus a self-consistency check (the output actually passes the module's
  own Miller-Rabin) and a structural check (exactly `prime_bits` long, top
  and bottom bit set).
- **`Proof`**: round-trip + wrong-length-rejection codec tests.
- **`group`**: the RSA-2048 challenge modulus is exactly 2048 bits and
  round-trips through its own codec; `elementFromBytes` is tested against
  all three documented rejection cases (`0`, `N` itself, `N+1`) plus the
  ordinary-value accept path.
- **`prove`/`verify`** (running): completeness across several `(x, T)`
  pairs including `T=0`-adjacent small values and `T=10_000`; soundness
  against a `y` off by exactly one squaring, a single-bit-tampered `π`, a
  wrong `T`, and every one of `x`/`y`/`π` being `0` or non-canonical
  (`>= N`). Plus a standalone naive-vs-streaming cross-check of the
  quotient (`std.math.big.int` `shiftLeft`→`divFloor` vs.
  `streamingQuotientPow`) across `t ∈ {1, 17, 255, 256, 257, 300, 1000}`,
  covering the `q=0`, `q=1`-boundary, and multi-bit-quotient cases.

No published third-party `(N, x, T) -> (y, π)` fixture was found for the
RSA-Wesolowski construction specifically (searched: Chia-Network's
`vdf-competition`/`oldvdf-competition`, `iotaledger/vdf`,
`poanetwork/vdf` — all three implement Wesolowski, but over a CLASS group,
not RSA `Z_N*`, and none publishes byte-level fixtures suitable for
cross-language embedding regardless of group). The `eval`/`hashToPrime`
vectors above are the closest available substitute: genuine cross-language
(Python) and cross-formula (Euler shortcut) verification of the REAL code
in this module. For `prove`/`verify` specifically — where no byte-exact
third-party RSA-Wesolowski oracle exists to find — verification rests on
property + soundness (completeness round-trips, the four documented reject
cases, and the `y`-binding proven by the wrong-`y` reject) plus the
independent naive-vs-streaming quotient cross-check; this is inherent to
the construction's absence of public byte vectors, and stated honestly
rather than papered over.

## Non-goals / follow-ups

- **Class-group variant (no trusted setup).** Out of scope for this
  module — a materially different (and more complex) group
  implementation, ideal-class arithmetic instead of modular arithmetic.
  Worth a future module (`vdf-classgroup` or similar) if a no-trusted-
  setup VDF becomes a real consumer need; not scaffolded here.
- **Pietrzak's VDF.** A different (non-Wesolowski) proof construction with
  different tradeoffs (larger proofs, no unknown-order-group requirement
  in some variants); not pursued here — Wesolowski's smaller,
  single-element proof is the more broadly adopted choice for an RSA-group
  VDF.
- **Multi-party "RSA-UFO" trusted-setup ceremony** for a caller-supplied
  `N`. Out of scope; this module documents the caveat and takes `N` as a
  parameter rather than implementing a ceremony.

## References

- Wesolowski, "Efficient Verifiable Delay Functions", IACR ePrint
  2018/623 (eprint.iacr.org/2018/623) — the primary construction this
  module follows (§3).
- Boneh, Bünz, Fisch, "A Survey of Two Verifiable Delay Functions", IACR
  ePrint 2018/712 (eprint.iacr.org/2018/712) — §2.3 (the low-order
  assumption underlying soundness) and §2.4 ("Simple Verifiable Delay
  Functions", the efficient/streaming prover technique `prove`'s doc
  comment specifies).
- RSA Factoring Challenge / "RSA numbers" — the source of the RSA-2048
  modulus this module embeds; see [NOTICE](NOTICE).
