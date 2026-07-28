# spake2plus — SPEC

SPAKE2+, an AUGMENTED (asymmetric) PAKE, per RFC 9383 —
P-256/SHA-256/HKDF-SHA256/HMAC-SHA256 ciphersuite; see [README.md](README.md)
for purpose and API. Provenance: see [NOTICE](NOTICE).

**Status: complete.** Ciphersuite constants, wire encoders, and the seven
crypto cores (`computeW0W1`, `computeL`, `proverStart`, `verifierStart`,
`deriveKeys`, `proverFinish`, `verifierFinish`) are all implemented — no
`@panic`/TODO stub remains in `root.zig`. See "The seven crypto cores"
below for what each does and how it is anchored.

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
- **The group**: `std.crypto.ecc.P256`, a PRIME-order Weierstrass curve
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

## `w0`/`w1` derivation (RFC 9383 §3.2) — the one function with no KAT oracle

`computeW0W1` implements §3.2's RECOMMENDED PBKDF-output-splitting
method (`w0s || w1s = pbkdf_output`, each half `>= 320` bits, reduced
mod `p` via `Scalar.fromBytes48`'s wide reduction). RFC 9383 Appendix
C's own test vector explicitly SKIPS this step ("the choice of PBKDF is
omitted, and values for w0 and w1 are provided directly") — so unlike
every other function in this module, `computeW0W1` has no official
byte-exact target. Its contract is still pinned unambiguously (via
`group_order`/`Scalar.fromBytes48`'s well-defined semantics, restated in
its own doc comment), just without a KAT to check it against; see
`kat_test.zig`'s coverage note.

## Threat model / limits

- **Ephemeral randomness**: `x`/`y` (the Prover's/Verifier's per-session
  scalars) MUST come from a CSPRNG (RFC 9383 §6: "The ephemeral
  randomness used by the Prover and Verifier MUST be generated using a
  cryptographically secure Pseudorandom Number Generator"). This module
  takes `x`/`y` as explicit CALLER-supplied parameters (mirrors
  `bip340.sign`'s `aux_rand` precedent) rather than generating them
  internally — sourcing them correctly is the caller's responsibility.
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
   halves, wide-reduce each mod `p` via `Scalar.fromBytes48`. No KAT
   oracle (see above) — correctness rests on `group_order`/
   `Scalar.fromBytes48`'s own well-defined semantics.
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
`kat_test.zig`. `computeTranscript` and `mac` pass against this same
vector too — the transcript/MAC plumbing the six cores feed into is
correct independent of them. The property-test layer (end-to-end
Prover<->Verifier agreement on `K_shared`, tamper rejection of a
corrupted confirmation MAC or a corrupted share) provides a SECOND,
independent correctness signal beyond the byte-exact numbers.

## Verification

- `zig build test-spake2plus` and `-Doptimize=ReleaseFast` both go green;
  `zig fmt --check modules/spake2plus/` clean.
- Disk-vs-running test count (CONVENTIONS.md §6 step 3):
  `grep -c '^\s*test ' modules/spake2plus/src/*.zig` summed across files
  equals `zig build test-spake2plus --summary all`'s reported total.
