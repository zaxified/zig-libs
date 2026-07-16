# bulletproofs — SPEC

Bulletproofs zero-knowledge range proofs over Ristretto255; see
[README.md](README.md) for purpose and API. Provenance: see
[NOTICE](NOTICE).

**Status: complete.** Generators, transcript, scalar/vector helpers, and
both proof structs' byte codecs are implemented for real. The two
irreducible zero-knowledge cores — the Inner-Product Argument (`ipa.zig`'s
`proveIpa`/`verifyIpa`) and the range-proof polynomial
construction/reduction (`rangeproof.zig`'s `prove`/`verify`) — are
implemented (Fable core pass) and `gate.core_implemented` is `true`, so
the full completeness + soundness KAT suite runs (50 tests, green in Debug
+ ReleaseFast). See "Caveats" below for the non-constant-time and
Linux-only-proving notes.

## Design

- **Source of truth**: Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell,
  "Bulletproofs: Short Proofs for Confidential Transactions and More",
  IEEE S&P 2018 (eprint.iacr.org/2017/1066) — consumed directly from the
  eprint PDF's §3 (Inner-Product Argument) and §4.1/§4.2 (the range
  proof). This is an academic paper, not an RFC/IETF spec, but is public
  and not itself a copyrightable implementation (no source code
  accompanies the paper text being cited) — see `NOTICE`.
- **Group**: Ristretto255 (`std.crypto.ecc.Ristretto255`), a prime-order
  group built on Edwards25519 (RFC 9496) — chosen because it is the group
  std already ships full support for (`add`/`sub`/`dbl`/`mul`/
  `basePoint`/`fromBytes`/`toBytes`/`fromUniform`/`equivalent`,
  `.scalar`'s complete field arithmetic including `reduce64` and
  constant-time `invert`) and because it is a genuine PRIME-order group
  (no cofactor subtleties to reason about in the IPA's recursive
  point-folding, unlike a raw Edwards25519/secp256k1 group with a
  cofactor). The sibling `frost`/`voprf` modules are the other
  Ristretto255-based modules in this repo and were consulted for
  scalar-representation and `meta`-tag conventions (see `root.zig`).
- **Scalars are raw `[32]u8`**, not a wrapper struct — the same
  convention `voprf` uses (its `root.zig` doc comment documents the
  rationale): `std.crypto.ecc.Ristretto255.scalar`'s own free functions
  (`add`/`sub`/`mul`/`mulAdd`/`neg`/`reduce64`) already operate directly
  on `[32]u8` (`CompressedScalar`), so introducing a wrapper type would
  only add unwrap/rewrap ceremony with no safety benefit (unlike, say,
  `frost`'s `SigningShare`/`SignatureShare`, which are DISTINCT wire types
  specifically to prevent accidental mixing — this module has no
  analogous mixing risk since every scalar here is either a public
  transcript value or a proof response field with a name-scoped role).
- **Scope: single-value range proofs only** (the paper's `m = 1`
  aggregation case — one commitment `V`, one range proof). §4.3's
  AGGREGATED range-proof extension (proving several `V_1..V_m` values in
  one combined proof, sharing one IPA call across all of them) is
  explicitly OUT of scope for this scaffold. Adding it later is a
  `rangeproof.zig`-local extension (a new `proveAggregated`/
  `verifyAggregated` pair reusing the same `Generators`/`Transcript`/`ipa`
  machinery, sized `m*n` instead of `n`) — it does not touch
  `generators.zig`/`transcript.zig`/`scalarvec.zig`/`ipa.zig` at all.
- **`v` is a plain `u64`**, not a bignum. Every realistic Bulletproofs
  range width (8/16/32/64 bits — the paper's own running example is `n =
  64`, "prove a value fits in a `uint64`") fits in a `u64` witness. A
  wider-`v` variant (`n > 64`) would need a bignum witness type
  (`std.math.big.int` or a fixed-width byte array) threaded through
  `prove`'s bit-decomposition step; that is a mechanical widening, not a
  new cryptographic core, and is left for whoever needs `n > 64` (no
  concrete consumer in this repo currently does).

## Inner-Product Argument (`ipa.zig`) — the recursive fold

The statement: given public `n`-length generator vectors `G_vec`/`H_vec`,
a public point `Q`, and a public point `P`, prove knowledge of secret
`n`-length vectors `a`/`b` with `P = <a,G_vec> + <b,H_vec> + <a,b>*Q`.
`n` must be a power of two (the paper's own recursion requirement — each
round halves the vector length exactly). See `ipa.zig`'s own module doc
comment for the complete per-round construction (5 numbered steps) and
the verifier's fold-and-check equation — that doc comment IS this
section's normative content; it is not repeated here (CONVENTIONS.md's
single-source-of-truth rule — one fact, one place).

**Why this is the Fable-hard core, restated**: every other function in
this module is either ordinary hashing/EC arithmetic with no
cryptographic JUDGMENT, or mechanical codec plumbing. The IPA's per-round
fold direction (which half multiplies `u` vs `u^{-1}`, and on which side
— prover's `a`/`b` fold one way, the verifier's `G_vec`/`H_vec` fold the
OPPOSITE way, by design, so the two meet at the same final check) is easy
to get backwards and produce something that LOOKS plausible (compiles,
runs, even happens to pass a lazy "does verify(prove(x)) == true" smoke
test with a bug that only breaks SOUNDNESS, not completeness) while
actually being unsound. This is exactly why `kat_test.zig`'s soundness
suite (tamper-rejection, cross-commitment rejection) is as heavily
weighted as it is — completeness alone cannot catch a fold-direction bug
that happens to be self-consistent.

## Range proof (`rangeproof.zig`) — the polynomial construction

The statement: given a public Pedersen commitment `V = v*G + gamma*H` and
a public bit-width `n`, prove `v ∈ [0, 2^n)` without revealing `v`/
`gamma`. See `rangeproof.zig`'s own module doc comment for the complete
10-step prover construction and the verifier's two checks (the `t_hat`
relation + the IPA) — again, that doc comment is this section's normative
content.

**`deltaYZ` (REAL)**: the verifier's `delta(y,z)` scalar correction term
(paper eq. (39), single-value case) is pure public-input arithmetic (`y`,
`z`, `n` — no witness) and is implemented for real, tested against a
hand-derived value computed by a DIFFERENT method than the implementation
itself (`rangeproof.zig`'s test block) to avoid a circular test. This is
the one piece of the verifier's own logic that could be pulled out and
implemented ahead of the two full cores, and doing so gives the eventual
Fable pass one fewer thing to get right from scratch.

**`commit` (REAL)**: the Pedersen value commitment `v*gens.g +
gamma*gens.h`. Trivial, but worth calling out: it uses `gens.g`/`gens.h`
(the two BASE points), never `gens.g_vec`/`gens.h_vec` (the two VECTOR
generator sets) — a mixup here would silently break every downstream
check since the range proof's `t_hat` relation (paper eq. (72))
specifically ties `V` to `gens.g`/`gens.h`, not the vectors.

## Generators (`generators.zig`) — NUMS derivation

`SHA-512(domain || label || suffix) -> Ristretto255.fromUniform`. See
`generators.zig`'s module doc comment for the full rationale (the
independence property this construction needs to provide, and why a
plain domain-separated SHA-512 chain is exactly as sound as a more
elaborate XOF-based one here, given there is no cross-implementation
byte-exactness target — see "Transcript" below for the identical
reasoning applied to Fiat-Shamir challenges).

`Generators.init` is a **pure, stateless, deterministic function of
`(domain, n)`** — no randomness, no I/O, no persisted state. This is
deliberate: a prover and a verifier that both call `Generators.init(gpa,
n)` with the same `n` always get byte-identical generators without ever
communicating them, which is the entire value of a NUMS construction
(neither party needs to transmit or trust the other's copy, and neither
can have secretly chosen a generator with a known discrete-log relation
to another).

## Transcript (`transcript.zig`) — module-defined, not dalek/Merlin-compatible

dalek's `bulletproofs` crate uses Merlin (a STROBE-based transcript
protocol — itself a distinct cryptographic primitive with its own
specification, not merely "a hash function") to bind public
values/prover messages into each Fiat-Shamir challenge. This module does
NOT depend on Merlin/STROBE:

1. **CONVENTIONS.md's zero-dep / "prefer std, build a dep only where std
   has a real gap" rules** point away from importing a second unrelated
   primitive (STROBE's sponge/duplex construction) purely to reproduce
   one module's proof format.
2. **This repo has no existing STROBE/Merlin implementation** to build
   on, and one does not currently exist anywhere else in `zig-libs` —
   building one from scratch to serve a single caller is exactly the
   kind of unnecessary dependency §1's directive warns against.
3. **The Bulletproofs paper itself does not mandate a transcript
   construction** — Fiat-Shamir instantiation is always
   implementation-defined (Merlin is dalek's *choice*, not the paper's
   requirement). This repo's `threshold_ecdsa` module documents the
   identical situation for its own Πprm/Πmod proofs (`aux_proofs.zig`'s
   header comment) and reaches the same conclusion: a self-contained,
   well-documented, domain-separated hash-based transcript is a fully
   legitimate Fiat-Shamir instantiation, not a lesser one.

**Consequence**: a proof produced by this module's `prove`/`proveIpa`
verifies ONLY against this module's own `verify`/`verifyIpa`. It is
internally self-consistent — soundness and completeness both hold
end-to-end within this module — but is **not** a wire-compatible
Bulletproofs proof against dalek, libsecp256k1-zkp, bulletproofs-js, or
any other implementation. Nothing in this module claims otherwise; every
doc comment that could be misread that way says so explicitly.

**This is why the KAT harness is property/soundness-based, not
byte-exact.** There is no third-party vector this module COULD match —
every published Bulletproofs test vector is tied to its producing
implementation's specific transcript. `kat_test.zig` instead verifies:

1. **Completeness** — an honestly-constructed proof for an in-range value
   verifies (several values including the boundary `v = 2^n - 1`), and a
   standalone IPA proof for an honestly-built `P` verifies.
2. **Soundness — out-of-range rejected at construction.** `prove` itself
   refuses `v >= 2^n` (`error.ValueOutOfRange`) before ever touching the
   stub body — this specific soundness scenario is real and UNGATED
   today (see `rangeproof.zig`'s `ProveError` doc comment).
3. **Soundness — exhaustive tamper suite.** Every proof field (`A`, `S`,
   `T1`, `T2`, `tau_x`, `mu`, `t_hat`, each IPA `L_i`/`R_i`, and the
   final `a`/`b`) is independently flipped and re-verified; each must be
   rejected.
4. **Soundness — cross-commitment rejection.** A proof produced for
   commitment `V` must not verify against a different commitment `V'`.
5. **Soundness — generator/parameter mismatch rejection.** A proof
   produced under an `n`-sized `Generators` set must not verify against
   a differently-sized set.
6. **Codec round-trips** (`InnerProductProof`/`RangeProof` byte
   encode/decode) — real and ungated, exercised with hand-constructed
   proof values so they do not depend on `prove`/`proveIpa` working.

No numeric reference values from a third-party implementation are
embedded (see the transcript incompatibility above) — the
property+soundness suite above IS this module's complete verification
methodology, at every stage (scaffold and post-Fable alike), not merely
a scaffold-stage placeholder pending a "real" KAT.

## Gate (`gate.zig`)

One flag, `core_implemented`, covers BOTH `ipa.zig` and `rangeproof.zig`:
`rangeproof.prove`/`.verify` cannot be exercised without
`ipa.proveIpa`/`.verifyIpa` already working (the range proof's last step
IS a call into the IPA), so there is no intermediate state where one core
is done and testable but the other isn't — see `gate.zig`'s own doc
comment.

## Caveats

- **Proving is Linux-only.** `rangeproof.prove` draws its secret blinding
  (`alpha`/`rho`/`s_L`/`s_R`/`tau1`/`tau2`) from `getrandom(2)` directly
  (`rangeproof.zig`'s `fillRandom`, `@compileError` on any non-Linux
  target — a predictable-blinding range proof leaks the witness, so this
  never silently degrades to a weaker entropy source). `verify`/
  `verifyIpa`/`commit`/`deltaYZ`/`proveIpa` (witness passed in as
  parameters) and both byte codecs are platform-independent; only the
  internal-entropy `prove` path is gated. `meta.platform` is therefore
  `.linux` (not `.any`) — the honest tag for the most-restrictive
  reachable path. Porting `fillRandom` to a POSIX/Windows entropy call
  would lift the restriction.
- **Not constant-time.** `scalarvec.multiScalarMul` skips zero scalars (a
  `catch continue` on std's "result is the identity element" error), so
  the time to form commitment `A` — built over the secret bit-vectors
  `a_L`/`a_R` — depends on the committed value's bit pattern (a mild
  prover-side timing side-channel). A range proof's PRIVACY rests on the
  proof's zero-knowledge property (the proof reveals nothing about `v`),
  not on constant-time proving, so this does not weaken the ZK guarantee;
  it is recorded here for honest threat-modelling of the prover host.

## Out of scope (future extensions)

- §4.3 aggregated multi-value range proofs (proving several `V_1..V_m` in
  one combined proof) — a `rangeproof.zig`-local extension reusing the
  same `Generators`/`Transcript`/`ipa` machinery.
- A Pippenger/windowed `multiScalarMul` (performance only, see
  `scalarvec.zig`'s doc comment).
- `n > 64` bignum witness support (see the `v` is a `u64` note above).
