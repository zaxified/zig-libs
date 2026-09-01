# spake2plus — SPEC

SPAKE2+, an AUGMENTED (asymmetric) PAKE, per RFC 9383 —
P-256/SHA-256/HKDF-SHA256/HMAC-SHA256 ciphersuite; see [README.md](README.md)
for purpose and API. Provenance: see [NOTICE](NOTICE).

**Status: complete.** Ciphersuite constants, wire encoders, and the seven
crypto cores (`computeW0W1`, `computeL`, `proverStart`, `verifierStart`,
`deriveKeys`, `proverFinish`, `verifierFinish`) are all implemented — no
`@panic`/TODO stub remains in `root.zig`. See "The seven crypto cores"
below for what each does and how it is anchored. An eighth function,
`verifierConfirm`, was added additively so the real protocol is drivable
by two genuinely blind parties — see "Driving the real, blind protocol"
below.

## Design

- **Source of truth**: RFC 9383, §3 (protocol definition), §3.2
  (offline registration), §3.3 (online authentication), §3.4 (key
  schedule/confirmation), §4 (ciphersuites), Appendix A (pseudocode),
  Appendix B (M/N point generation — informational only, this module
  transcribes the RESULT, not the generation algorithm itself), Appendix
  C (test vectors). Only the P-256/SHA-256/HKDF-SHA256/HMAC-SHA256
  ciphersuite (§4's first table row) is implemented — the one Matter/
  Thread device commissioning uses (see `NOTICE`'s consumer note).
- **RFC 9383 vs. RFC 9382 — do not conflate.** RFC 9382 is plain,
  BALANCED SPAKE2 (a separately-numbered companion spec): both sides
  hold the SAME symmetric secret `w`, with no `w0`/`w1` split and no
  registration record. RFC 9383 (THIS module) is the AUGMENTED variant:
  the Prover holds `w0` AND `w1`; the Verifier holds `w0` AND `L =
  w1*P`, NEVER `w1` itself. Every asymmetric artifact in this module —
  the `w0`/`w1` split, `L`, the two DIFFERENT routes each side takes to
  the same `V` value (see "The `V` trick" below) — exists because of
  this augmentation. `root.zig`'s `meta.model_after` and its own test
  ("names RFC 9383 / SPAKE2+ (not RFC 9382 / plain SPAKE2)") both pin
  this distinction so it cannot silently drift.
- **The group**: this repository's `p256` module (byte-exact to
  `std.crypto.ecc.P256`, which is what this module was written against
  and was moved off on 2026-07-19), a PRIME-order Weierstrass curve
  — cofactor `h = 1` always for this ciphersuite (`cofactor_h` in
  `root.zig`), so every `h*x*(...)`/`h*y*(...)` term in RFC 9383's `Z`/
  `V` equations collapses to a no-op multiplication-by-one. This is a
  documented simplification specific to P-256 — a hypothetical
  edwards25519/edwards448 ciphersuite (RFC 9383 also specifies these,
  out of scope here) would have `h != 1` and could not skip this term.
- **`M`/`N`** (RFC 9383 §4): fixed, discrete-log-unknown P-256 points,
  transcribed byte-exact from the RFC's ciphersuite table (compressed
  SEC1, 33 bytes each) — see `NOTICE` for the transcription and
  cross-check method. `mPoint()`/`nPoint()` parse them into real curve
  points at call time (not comptime — `fromSec1`'s `recoverY`/`sqrt` is
  not comptime-friendly at this repo's `@setEvalBranchQuota` budget).
- **Point encoding — UNCOMPRESSED SEC1, not compressed**: every group
  element that crosses this module's API boundary or enters the
  transcript (`shareP`, `shareV`, `Z`, `V`, `L`, and `M`/`N` INSIDE the
  transcript) is 65-byte uncompressed SEC1 (`0x04 || X (32) || Y (32)`),
  per RFC 9383 Appendix C's own statement for its test vectors and
  independently confirmed by extracting `M`/`N` directly out of the
  published `TT` bytes at their known offset (see `NOTICE`). This is
  DIFFERENT from RFC 9383 §4's ciphersuite table, which prints `M`/`N`
  compressed (33 bytes) — a compact way to list the constants, not the
  wire/transcript format actually used. `root.zig`'s `share_length`
  constant documents this distinction at its point of use.
- **Length-prefix width — 8-byte LITTLE-endian, not big-endian**: RFC
  9383 §3's own glossary is explicit ("len(S) denote[s] the length of a
  string in bytes, represented as an eight-byte little-endian number").
  This is the single easiest byte-exact mistake in the whole module —
  `computeTranscript`'s doc comment calls it out directly, and
  `kat_test.zig`'s "REAL TODAY" transcript test is the concrete,
  currently-passing proof that this implementation got it right.
- **Transcript field order** (RFC 9383 §3.4 / Appendix A.3): `Context,
  idProver, idVerifier, M, N, shareP, shareV, Z, V, w0` — ten
  length-prefixed fields, no more, no fewer, in exactly this order.
  `M`/`N` are ciphersuite-fixed constants, NOT function parameters
  (`computeTranscript`'s signature omits them, matching RFC 9383
  Appendix A.3's own `ComputeTranscript(Context, idProver, idVerifier,
  shareP, shareV, Z, V, w0)` — no `M`/`N` parameters there either).

## The `V` trick — why the Verifier never needs `w1`

This is SPAKE2+'s central asymmetric-PAKE mechanism, and the reason this
module is NOT a relabeled copy of plain SPAKE2 (`root.zig`'s module doc
comment states the conclusion; this section derives it).

The Prover computes `V = h*w1*(Y - w0*N)`. The Verifier computes `V =
h*y*L`. These are DIFFERENT computations — different operand sets
entirely (`w1` and a session-derived point vs. `y` and the
REGISTRATION RECORD `L`) — yet, for a Prover and Verifier who share the
SAME password (hence the same `w0`/`w1`, hence `L = w1*P`), they land on
the IDENTICAL group element:

```text
Y - w0*N = y*P + w0*N - w0*N = y*P          (VerifierStart's own definition of Y)
w1*(Y - w0*N) = w1*(y*P) = y*(w1*P) = y*L    (scalar multiplication commutes)
```

So `h*w1*(Y-w0*N) == h*y*L` whenever both sides used the SAME `w0`/`w1`
pair to derive `Y`/`L` in the first place — and this holds WITHOUT the
Verifier ever needing to know `w1`, only `L`. If the Prover's `w1` does
NOT match the `w1` that produced the Verifier's stored `L`, the two `V`
computations land on DIFFERENT points, the resulting transcripts (and
hence `K_main`/`K_confirmP`/`K_confirmV`) diverge, and key confirmation
fails — exactly the property that authenticates password knowledge.

Compare this to plain SPAKE2 (RFC 9382), where BOTH sides hold the
identical `w` and there is no analogous "prove knowledge of `w1` via a
one-way function of it" step at all — SPAKE2's Verifier-equivalent party
holds the literal secret, so a database compromise there IS a stolen
password. SPAKE2+'s `L` is the whole reason that is not true here.

## `w0`/`w1` derivation (RFC 9383 §3.2) — the one function Appendix C cannot reach

`computeW0W1` implements §3.2's RECOMMENDED PBKDF-output-splitting
method (`w0s || w1s = pbkdf_output`, each half `>= 320` bits, reduced
mod `p` via `Scalar.fromBytes48`'s wide reduction). RFC 9383 Appendix
C's own test vector explicitly SKIPS this step ("the choice of PBKDF is
omitted, and values for w0 and w1 are provided directly") — so unlike
every other function in this module, `computeW0W1` has no *official*
byte-exact target.

It is not unanchored, though. `src/bssl_w0w1_vectors.zig` carries frozen
outputs of BoringSSL's `bssl::spake2plus::Register` performing the
identical §3.2 construction, and `src/bssl_w0w1_test.zig` pins
`computeW0W1` (and `computeL`) against them byte for byte — three
registration vectors plus chosen modular-reduction boundary halves
(`0`, `1`, `n-1`, `n`, `n+1`, `2^256-1`, `2^320-1`), which a scrypt
output never lands near and which the §3.2 wide reduction is precisely
what gets wrong. That is a genuine cross-implementation oracle, not a
self-consistency check; it closed audit finding F1.

## Threat model / limits

- **Ephemeral randomness**: `x`/`y` (the Prover's/Verifier's per-session
  scalars) MUST come from a CSPRNG (RFC 9383 §6: "The ephemeral
  randomness used by the Prover and Verifier MUST be generated using a
  cryptographically secure Pseudorandom Number Generator"). This module
  takes `x`/`y` as explicit CALLER-supplied parameters (mirrors
  `bip340.sign`'s `aux_rand` precedent) rather than generating them
  internally — sourcing them correctly is the caller's responsibility.

  **"A CSPRNG" is not specific enough in this repository, and the
  difference is the whole security of the PAKE.** `std.Io.random` is a
  CSPRNG *by its own documentation* and carries a silent-degrade clause
  (`std.Io.Threaded` seeds from a zeroed buffer plus an ASLR pointer,
  `getpid()` and a clock when entropy is unavailable). `x`/`y` are
  secret-bearing draws, so CONVENTIONS.md §2.2 applies: use
  `try io.randomSecure(&buf)`, or [`entropy.fill(io, &buf)`](../entropy)
  where there is no error channel — the same rule, and for the same
  reason, that `bip340`'s `a_2..a_u` draws follow.

  What a degraded draw costs here: `shareV = y*P + w0*N` is public. An
  eavesdropper who can predict `y` recovers `w0*N = shareV - y*P`, and
  then each candidate password costs ONE scalar multiplication to test,
  **offline, with no further interaction** — the augmented PAKE collapses
  to the offline dictionary attack it exists to prevent. The Prover side
  is symmetric in `x` and `w0*M`. Reduce the draw to a wide 48-byte
  buffer with `Scalar.fromBytes48` (the pattern `computeW0W1` already
  uses) rather than rejection-sampling by hand.
- **Rate-limit failed runs**: a PAKE's security argument is that an
  active attacker gets exactly ONE password guess per protocol run, and
  that argument holds only if the Verifier bounds how many runs an
  attacker may start. This module has no state and cannot count for you:
  every `error.ConfirmationMismatch` from `verifierFinish` is one
  consumed guess against `(idProver, idVerifier)` and the caller must
  record it, throttle, and lock out. ⚠ **RFC 9383 does not say this** —
  its §6 covers the CSPRNG and subgroup-confinement requirements and is
  silent on failed-attempt limiting (checked against the RFC text, not
  assumed), so an implementer who treats §6 as a complete checklist ships
  an unthrottled Verifier. The obligation comes from what a PAKE is, not
  from the document.
  Abort the session on the error; never retry the same run, and never
  report *why* it failed to the peer. For the Matter/Thread commissioning
  passcodes this ciphersuite targets the search space is 10^8 or smaller,
  so an unthrottled Verifier is brute-forceable online.
- **Group-membership checks are mandatory, not optional**: RFC 9383 §6
  requires aborting on any received public value `V` such that `V*h ==
  I` (the identity). For P-256's prime-order group (`h = 1`), this
  reduces to "the value parses as a valid, on-curve, non-identity SEC1
  point" — `proverFinish`/`verifierFinish`'s `InvalidShareV`/
  `InvalidShareP` errors are this check; skipping it (e.g. accepting the
  identity point as a valid `shareV`) would allow a small-subgroup-style
  degenerate-input attack even though P-256 itself has no small
  subgroups to confine into (the identity element is always a
  degenerate case regardless of cofactor).
- **Constant-time discipline**: EVERY scalar multiplication in this
  module's cores touches SECRET material on at least one side (`x`,
  `y`, `w0`, `w1` are all password- or session-derived) — `computeL`,
  `proverStart`, `verifierStart`, and the `Z`/`V` computations inside
  `proverFinish`/`verifierFinish` MUST all use `P256`'s constant-time
  `mul`/`add`/`sub`, never `mulPublic`/`mulDoubleBasePublic` (those are
  reserved, elsewhere in this repository, for PUBLIC-input verification
  equations like `bip340.verify`'s — there is no such "all-public-input"
  equation anywhere in this module, unlike a signature-verify scheme).
- **Key-confirmation MUST be constant-time-compared and MUST gate
  `K_shared` use**: RFC 9383 §3.3: "Both parties MUST NOT consider the
  protocol complete prior to receipt and validation of these key
  confirmation messages" and Appendix A.5's own pseudocode uses
  `not_equal_constant_time`. `proverFinish`/`verifierFinish`'s
  `ConfirmationMismatch` error is this gate; a specialist implementing
  the stub MUST use a constant-time comparison for the received-vs-
  expected confirmation MAC (NOT `std.mem.eql`, which is variable-time),
  the same discipline `bip340`'s self-verify / `adaptor`'s tamper checks
  already establish elsewhere in this repository for MAC/signature
  comparisons that gate a security-relevant accept/reject decision.
- **`K_main` and the confirmation keys MUST be discarded after use**:
  RFC 9383 §3.4: "Neither K_main nor its derived confirmation keys are
  used for anything except key derivation and confirmation and MUST be
  discarded after the protocol execution." This module returns them in
  `ProverFinishResult`/`VerifierFinishResult` for KAT-testing visibility
  (requirement (5) in `root.zig`'s module doc comment) — a production
  caller that is NOT testing against a KAT should zero them once
  `K_shared` has been extracted, the same "sensitive intermediate values
  are the caller's to scrub" division of labor this repository's other
  crypto modules leave to their callers (no built-in secure-erase
  primitive is assumed here).
- **`L` must be the record actually registered for THIS Prover
  identity**: `verifierFinish` takes `l` as a plain parameter rather
  than looking it up internally — binding `l` to the correct
  `(idProver, idVerifier)` pair is a PROTOCOL/storage-layer concern this
  module has no way to enforce (mirrors `adaptor.preVerify`'s note that
  binding an adaptor point to the right protocol context is the
  caller's job, not the primitive's).

## The seven crypto cores (all implemented)

The seven crypto cores in `root.zig` are all real — no `@panic`/TODO stub
remains. Each function's own doc comment spells out the exact RFC 9383
construction step-by-step, following the sibling `bip340`/`frost`/
`adaptor` modules' established idioms (constant-time multiply-then-add
for secret-touching scalar ops, `Scalar.fromBytes48` wide reduction,
allocator-owned variable-length output, constant-time MAC/confirmation
comparison):

1. **`computeW0W1`** — split an 80-byte PBKDF output into two 40-byte
   halves, wide-reduce each mod `p` via `Scalar.fromBytes48`. Outside
   Appendix C's reach (see above), so it is anchored instead against
   BoringSSL's `Register`, boundary halves included.
2. **`computeL`** — `L = w1*P` (constant-time base-point multiply,
   uncompressed-SEC1-encode).
3. **`proverStart`** — `X = x*P + w0*M` (two constant-time multiplies +
   one add, uncompressed-SEC1-encode).
4. **`verifierStart`** — `Y = y*P + w0*N` (same shape, the other
   constant).
5. **`deriveKeys`** — `K_main = Hash(TT)`; `K_confirmP || K_confirmV =
   KDF("", K_main, "ConfirmationKeys")` (ONE 64-byte expand, split in
   two); `K_shared = KDF("", K_main, "SharedKey")`.
6. **`proverFinish`** — parse+group-check `shareV`; `diff = Y - w0*N`;
   `Z = diff*x`; `V = diff*w1`; assemble `TT`; `deriveKeys`; constant-
   time-check `received_confirm_v` against `MAC(K_confirmV, shareP)`;
   return `confirmP = MAC(K_confirmP, shareV)` plus `K_shared`.
7. **`verifierFinish`** — parse+group-check `shareP`/`l`; `diff = X -
   w0*M`; `Z = diff*y`; `V = l_point*y`; assemble `TT`; `deriveKeys`;
   return `confirmV = MAC(K_confirmV, shareP)`; constant-time-check
   `received_confirm_p` against `MAC(K_confirmP, shareV)`; return
   `K_shared`.

Byte-exact oracle for six of the seven: RFC 9383 Appendix C's OFFICIAL
P-256/SHA-256 test vector (`kat_vectors.zig`), exercised by
`kat_test.zig`. The seventh, `computeW0W1`, is anchored against
BoringSSL (`bssl_w0w1_vectors.zig` / `bssl_w0w1_test.zig`), which also
gives `computeL` a second, independent oracle.
`computeTranscript` and `mac` pass against this same
vector too — the transcript/MAC plumbing the six cores feed into is
correct independent of them. The property-test layer (a genuinely blind
end-to-end Prover<->Verifier run agreeing on `K_shared`, tamper rejection
of a corrupted confirmation MAC or a corrupted share) provides a SECOND,
independent correctness signal beyond the byte-exact numbers.

## Driving the real, blind protocol — `verifierConfirm`

`proverFinish` takes the Verifier's `confirmV` as an input and only then
produces the Prover's `confirmP`. `verifierFinish` takes the Prover's
`confirmP` as an input and only then produces the Verifier's `confirmV`
(plus `K_shared`). Read naively as the whole API, this is circular: each
function needs the OTHER party's confirmation value before it will run,
and two blind parties — neither of whom starts out knowing anything the
other hasn't sent — cannot resolve that on their own.

The circularity is not in the protocol; it was in the API surface.
RFC 9383 Appendix A.5's own pseudocode is not circular, because the two
roles are not symmetric in when they act: the Verifier computes and
transmits `confirmV` FIRST, with no `confirmP` in existence yet; only
after the Prover receives and validates that `confirmV` does it compute
and transmit `confirmP`; the Verifier's check of `confirmP` is the LAST
step of the whole protocol. `verifierFinish` models that last step
correctly (it is only ever called once `confirmP` genuinely exists) —
but nothing modeled the EARLIER step, the Verifier's confirmV emission,
which by construction cannot depend on `confirmP`.

`verifierConfirm` is that earlier step, added additively: the same
`Z = h*y*(X - w0*M)` / `V = h*y*L` / transcript / key-schedule
computation `verifierFinish` performs, stopping right after
`confirmV = MAC(K_confirmV, shareP)` — no `received_confirm_p` parameter,
because this step runs before that value exists, and `VerifierConfirmResult`
carries `confirm_v` and NOTHING ELSE. RFC 9383 §3.3 is explicit that neither
party may consider the protocol complete before validating the peer's
confirmation; a function that handed back `K_shared` before that
validation would reintroduce the exact class of defect this addition
fixes, only worse (a silently-unauthenticated key instead of a stuck
protocol).

⚠ **Omitting the `k_shared` FIELD is not what makes that true, and the
first version of this function got it wrong.** It also returned `tt` and
`k_main` "for KAT visibility", and each of those is a one-call pre-image of
`K_shared` through this module's own public `deriveKeys`/`kdf` — measured
2026-09-01: both `deriveKeys(vc.tt).k_shared` and
`kdf(32, "", &vc.k_main, "SharedKey")` equal the real `K_shared`, at the
moment the Verifier has never seen a `confirmP`. `Z`/`V` were two calls
away by the same route. All of them now stay inside the call, which frees
its own transcript; the byte-exact KAT coverage they carried is unchanged,
because `verifierFinish` recomputes and returns the same values on the same
inputs, after the confirmation check, where returning them is safe.

Scope this honestly: it is a gate against a caller's **mistake**, not
against a hostile Verifier. The Verifier holds `w0`, `L`, `y` and both
shares, so it can always recompute the key schedule from scratch if it
sets out to. What the type now guarantees is that it cannot do so by
accident, from a field it was handed while the docs told it that was
impossible. `proverFinish` needed no equivalent split: `proverStart`
already gives the Prover a way to emit its first message (`shareP`) with
no peer input, and by the time the Prover next acts it already holds
BOTH `shareV` and the Verifier's `confirmV` — the RFC's own pseudocode
has the Verifier transmit both of those before the Prover does anything
else, so `proverFinish`'s existing signature already matches the real
order.

The real, blind sequence is therefore: `proverStart` -> `verifierStart`
-> `verifierConfirm` (Verifier sends `confirmV`) -> `proverFinish`
(validates `confirmV`, sends `confirmP`, returns `K_shared`) ->
`verifierFinish` (validates `confirmP`, returns the matching
`K_shared`) — see README.md's "Protocol flow" for the runnable code, and
`kat_test.zig`'s "false anchor fix" test for a version that drives this
with the official RFC 9383 vector and no foreknowledge of either
confirmation value. Constant-time discipline is identical to
`verifierFinish`: `y`/`w0` are secret, so `mPoint().mul`/`l_point.mul`
use `P256`'s constant-time `mul`, never `mulPublic`/
`mulDoubleBasePublic`. Ownership follows the same pattern as the other
six cores: `verifierConfirm` allocates `TT` via `computeTranscript` and
returns it caller-owned in `VerifierConfirmResult.tt`.

## Verification

- `zig build test-spake2plus` and `-Doptimize=ReleaseFast` both go green;
  `zig fmt --check modules/spake2plus/` clean.

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** RFC 9383 Appendix C official P-256/SHA-256 vector, kat_vectors.zig; plus goldens captured from BoringSSL's `bssl::spake2plus::Register` (registration + modular-reduction boundary halves), bssl_w0w1_vectors.zig
