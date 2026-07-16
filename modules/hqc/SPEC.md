# hqc — SPEC

Part 1 (ring + PRNG foundation) of a multi-part HQC arc. See
[README.md](README.md) for purpose and API.

## Spec version + why this one

- **Spec**: "Hamming Quasi-Cyclic (HQC)", 22/08/2025,
  `pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf`.
- **Reference implementation**: `gitlab.com/pqc-hqc/hqc`, tag `v5.0.0`
  (commit `f46e5422`, tagged 2025-08-26, "Release v5.0.0"). Confirmed to
  be the exact implementation of the 22/08/2025 spec: the tag's KAT
  filenames (`kats/ref/hqc-1/PQCkemKAT_2321.rsp` etc.) encode
  `|dkKEM|` = 2321/4602/7333 bytes, which match this spec's Table 6
  exactly (an older spec/impl pairing would have different sizes — the
  2025/08/22 changelog entry reworked the keypair format, the FO
  transform, and the hash instantiation from SHAKE256 to SHA3-512/256,
  all of which move these byte counts).
- **Why this version over an older "round-4" snapshot**: the task was to
  target the version with published KAT vectors that corresponds to the
  NIST-selected parameters. `v5.0.0`/2025-08-22 is the HQC team's current
  released spec+implementation pairing, shipped with its own
  `kats/ref/hqc-{1,3,5}/PQCkemKAT_*.{req,rsp}` and
  `intermediates_values` files in the same tag — i.e. spec, code, and KAT
  are guaranteed mutually consistent because they're the same release.
  NIST has not yet published its own FIPS draft for HQC (expected after
  the 2026 sixth PQC standardization conference cycle); when it does,
  expect the same kind of revision Falcon saw going from Round-3 to
  FN-DSA (header/domain-separation changes, not ring/decoder math
  changes) — Part 3's KAT reproduction targets `v5.0.0` and should be
  revisited if/when a FIPS draft KAT appears.
- **KAT source for Part 3**: `kats/ref/hqc-{1,3,5}/PQCkemKAT_*.rsp`
  (fetched via `curl`, not a paraphrasing tool — see kat_vectors.zig) —
  count=0..99 keypair/ciphertext/shared-secret vectors, standard NIST
  `.rsp` format (`seed`/`pk`/`sk`/`ct`/`ss`). The 48-byte `seed` field
  feeds HQC's own `Prng` (see "PRNG" below) directly — **no AES-256-CTR-
  DRBG is needed**, confirmed by reading
  `packaging/utils/helpers/main_kat.c` (the actual `PQCgenKAT_kem.c`
  harness shipped in this release): it calls
  `prng_init(entropy_input, NULL, 48, 0)` then `prng_get_bytes(seed, 48)`
  per vector, and re-derives the same per-vector `seed` via a second
  `prng_init(seed, NULL, 48, 0)` before `crypto_kem_keypair`/`_enc`. This
  is a deliberate departure from the classic NIST harness (which normally
  wraps AES-256-CTR-DRBG) — HQC's own release replaces it with SHAKE256,
  which `std.crypto` already has.

## Design

- **Ring** (`gf2x.zig`): R = F2[X]/(X^n − 1), n prime for every real
  parameter set (17669/35851/57637). `Elem` is `ceil(n/64)` u64 words,
  LSB-first (bit i → word i/64, bit i mod 64) — this is a plain
  little-endian bitset convention and is what the reference's
  `vect_set_random`/`vect_print` produce (confirmed byte-exact, see
  Verification below), so no repacking is needed anywhere.
- **`mul`** implements the spec's convolution product w_k = Σ_{i+j≡k mod
  n} u_i·v_j directly: for every bit position of `a` (all n of them, not
  just set ones — see below), XOR a shift-and-mask of `b` into a
  double-width accumulator, then fold bits [n, 2n−2] back onto [0, n−2]
  (X^{n+j} ≡ X^j). This is mathematically identical to the reference's
  word-aligned Toom-Cook/Karatsuba + `pclmul` elementary multiply (spec
  §3.3, Table 2) but O(n²/64) instead of near-linear — **a deliberate
  Part-1 simplification**: this is the mechanical ring-arithmetic
  foundation, not the performance path, and n²/64 is still fast in
  practice (≈52M word-XORs for the largest parameter set, hqc-256,
  n=57637 — well under a second even in Debug). A Toom-Cook/Karatsuba
  rewrite is flagged as follow-up work, not required for Part 2/3
  correctness.
- **Constant-time posture**: `mul` iterates over every bit position of
  `a` unconditionally (never skips a zero bit) and selects each
  contribution via an arithmetic mask (`0 -% bit`), never a branch —
  mirroring the spec's explicit requirement (§3.3: "Multiplications ...
  are performed without taking account of the sparsity ... in order to
  avoid potential leakage of information"). The reduction fold is
  likewise branch-free (bit extraction + shift, no `if` on the bit's
  value). The fixed-weight samplers' duplicate-rejection scans
  (`prng.zig`) are full linear scans with no early exit, matching the
  reference's `vect_generate_random_support{1,2}` access pattern. **What
  is NOT claimed**: no dudect/ctgrind or other machine-checked
  side-channel verification has been run (same caveat this repo's
  `falcon` carries for its Gaussian sampler) — the structure matches the
  reference's, but that structural match itself hasn't been
  instrument-verified.
- **PRNG/XOF** (`prng.zig`): two independent SHAKE256 instantiations
  (spec Table 1, §3.1), distinguished only by a trailing domain-separator
  byte absorbed after the payload:
  - `Prng` (domain 0): `SHAKE256(entropy ‖ personalization ‖ 0x00)`,
    plain squeeze. This is HQC's own internal PRNG AND (per
    `main_kat.c`, see above) the NIST KAT harness's DRBG in this release.
  - `Xof` (domain 1): `SHAKE256(seed ‖ 0x01)`. Its `getBytes` has a
    **load-bearing quirk** inherited from the reference's
    `xof_get_bytes`: the underlying stream is always consumed in whole
    8-byte blocks. A request whose length isn't a multiple of 8 still
    returns exactly the requested bytes (the *content* is unaffected),
    but the stream position afterward advances to the next multiple of
    8, silently discarding the unused tail of that last block. This only
    matters when a context is *reused* across multiple `getBytes` calls
    (chained sampling: y then x in keygen; r2, e, then r1 in encryption;
    seed_pke then sigma when expanding seedKEM) — get it wrong and every
    call after the first non-aligned one desyncs from the reference.
    This was caught empirically during development: a first attempt at
    `Xof.getBytes` (a plain contiguous squeeze) reproduced `y` correctly
    but not the chained `x` — see kat_test.zig / prng.zig's module doc.
- **Fixed-weight sampling** (spec §3.2, Table 5's ω / ω_r=ω_e): HQC v5.0.0
  uses *two different* samplers depending on which vector is being drawn
  (spec's Keygen/Encrypt algorithm boxes, §3.5):
  - `sampleFixedWeightRejection` (the spec's `SampleFixedWeightVect$`,
    reference `vect_sample_fixed_weight1`) — unbiased, true rejection
    sampling: draw a 24-bit value from the XOF, reject ≥ a precomputed
    threshold (`floor(2^24/n)·n`), Barrett-reduce mod n, reject
    duplicates against the support built so far. Used **only** for
    keygen's secret vectors x and y.
  - `sampleFixedWeightBiased` (the spec's `SampleFixedWeightVect`,
    "Algorithm 5" from Aragon–Barreto–Persichetti eprint 2021/1631,
    reference `vect_sample_fixed_weight2`) — a single Lemire-style
    multiply-shift per element (`i + (rand·(n−i)) >> 32`) plus a
    constant-access-pattern duplicate-fixup pass; not perfectly uniform
    (the spec's 2023/04/30 changelog cites [36]'s analysis that the bias
    is cryptographically negligible). Used for encryption's r1, r2, e —
    i.e. every *ciphertext-randomness* vector, never the long-term secret
    key. This split (strict-uniform sampler for the key, cheaper biased
    sampler for per-encryption randomness) is the spec's own design
    choice, not a Part-1 simplification.
- **`prng` vs `gf2x` layering**: samplers write directly into a `[]u64`
  slice via `writeSupportToVector`, independent of any specific `Ring(n)`
  instantiation — callers pass `Ring(n).Elem[0..]` as that slice. This
  keeps `prng.zig` parameter-set-generic (n/weight are plain
  comptime/runtime numeric args) rather than requiring a `Ring` type
  parameter, which would otherwise force an awkward import cycle with
  `gf2x.zig`.

## Threat model / limits

- Part 1 has **no side-channel machine verification** (see "Constant-time
  posture" above) — structural match to the reference only.
- `gf2x.mul`'s O(n²/64) schoolbook algorithm is a correctness-first
  stand-in for the reference's Toom-Cook/Karatsuba; fine for KAT
  reproduction and even a modest-throughput KEM, but a real deployment
  wanting reference-level performance should revisit it (flagged as
  follow-up, not blocking Part 2/3).
- `sampleFixedWeightBiased` and `hashH`/`hashJ` are transcribed from the
  reference's C source with the same care as everything else here, but —
  unlike `Xof`, `Prng`'s construction, `hashI`, `hashG`, and
  `sampleFixedWeightRejection`/`sampleVect` — they are **not**
  independently numeric-KAT-pinned (see Verification below for exactly
  why: the reference's public `intermediates_values` fixture doesn't
  print r1/r2/e or exercise H/J directly). They're still believed correct
  (unambiguous C source, same construction pattern as the pinned
  primitives) but carry a lower confidence tier — flagged honestly rather
  than silently treated as equally verified.
- No key generation, encryption, decryption, or KEM operations exist in
  Part 1 — nothing here is usable as a KEM yet.

## Verification

**Per-primitive tier** (most → least verified):

| Primitive | Tier | Evidence |
|---|---|---|
| `Xof` (construction + `getBytes` quirk) | Numeric-KAT-pinned | kat_test.zig: chained y-then-x sampling reproduces the reference's `intermediates_values` exactly; this specifically caught the 8-byte-rounding quirk (an unaligned-length-squeeze bug reproduced `y` but not chained `x` until fixed) |
| `Prng` construction | Source-matched + KAT-source-confirmed | `packaging/utils/helpers/main_kat.c` shows it IS the NIST KAT DRBG in this release (see "Spec version" above); not separately numeric-pinned in Part 1 since Part 1 has no full keygen to run against a `.rsp` vector yet (that's Part 3) |
| `hashI` | Numeric-KAT-pinned | kat_test.zig: `I(seed_pke) == seed_dk ‖ seed_ek` exactly |
| `hashG` | Numeric-KAT-pinned | kat_test.zig: `G(H(ek_kem), m, salt) == K ‖ theta` exactly |
| `sampleVect` | Numeric-KAT-pinned | kat_test.zig: reproduces the reference's `h` exactly, including the top-word mask |
| `sampleFixedWeightRejection` + `writeSupportToVector` | Numeric-KAT-pinned | kat_test.zig: reproduces the reference's `y` and `x` (chained) exactly |
| `gf2x.mul`/`add`/`weight`/codecs | Algebraic self-test only | No official gf2x-level KAT is published (the reference ships no isolated multiply vectors — checked `tests/unit/test_vector.c`, it's property-based, no fixed multiply I/O); pinned instead via hand-verifiable monomial-wraparound cases (`X^i · X^j = X^{(i+j) mod n}`, including the mod-reduction wraparound) plus commutativity/distributivity/identity-element/weight-bound checks |
| `hashH`, `hashJ` | Source-matched only | Transcribed from `symmetric.c`; not independently numeric-pinned (see Limits above) |
| `sampleFixedWeightBiased` | Source-matched + property-tested | Transcribed from `vector.c`'s `vect_generate_random_support2`; self-tested for exact weight / no duplicates / in-range, not numeric-KAT-pinned |

**How the numeric pins were obtained** (for future auditing): the
reference's `kats/ref/hqc-1/intermediates_values` file (shipped in the
same `v5.0.0` tag as the KAT `.rsp` files, produced by the reference's
"verbose" build mode) was downloaded via `curl` (not through any
summarizing/paraphrasing tool — hex transcription errors from an LLM
intermediary were an explicit risk considered and avoided this way) and
cross-verified independently in Python (`hashlib.sha3_512`/`shake_256`)
*before* being ported into `kat_vectors.zig`. That file is a standalone
illustrative run, not tied to the `.rsp`'s own count=0 `seed` — confirmed
by checking that `intermediates_values`' `K`/`ss` don't match the `.rsp`
count=0 vector's `ss`, ruling out an assumed-but-false seed relationship.
That's immaterial to what it's used for here: it's the reference's own
recorded output for *some* seed, and reproducing it byte-exact proves
this module's primitives match the reference's, independent of which
seed started the chain.

**What Part 1 could NOT pin**: end-to-end `.rsp` keypair/ciphertext/
shared-secret reproduction, since that requires the full PKE (`gf2x.mul`
composed with the Part-2 decoder) — deferred to Part 3.

## Arc plan

- **Part 1 (this module)** — ring + PRNG foundation. Tier: Sonnet
  (mechanical constant-structure bit arithmetic + exact PRNG-construction
  matching). **No part of Part 1 is genuinely Fable-hard** — the closest
  candidate, `gf2x.mul`'s constant-time structure, is a known, mechanical
  transformation (branch → mask) of an already-fully-specified reference
  algorithm, not an open algorithmic problem.
- **Part 2 — concatenated Reed-Muller/Reed-Solomon codec** (spec §3.4):
  the [n1n2, k] code C, built by concatenating a dimension-32 Reed-Solomon
  code over F256 (external) with a duplicated first-order Reed-Muller
  code RM(1,7) = [128,8,64] (internal, replicated 3× for hqc-128 or 5×
  for hqc-192/256 — `params.rm_multiplicity`). **This is the genuinely
  Fable-hard core of the HQC arc**: RM decoding via the fast Hadamard
  transform (maximum-likelihood over the duplicated code, "Green
  machine" per spec §3.4.3) composed with RS decoding via Berlekamp's
  algorithm for the error-locator polynomial plus an *additive* FFT
  (spec cites [17]) for root-finding over GF(2⁸) — additive FFTs are a
  meaningfully harder primitive than the multiplicative NTTs this repo
  already has (falcon, bls12_381), and getting the RS/RM composition's
  error-position bookkeeping exactly right (shortened-RS index offsets:
  RS-S1/S2/S3 subtract 209/199/165 from the standard RS-1/2/3 tables) is
  exactly the kind of fiddly, easy-to-get-subtly-wrong composition this
  repo reserves for Fable. Tier: **Fable**.
- **Part 3 — HQC-PKE + HQC-KEM, byte-exact vs NIST KAT**: compose Part 1
  (ring `mul`, samplers) with Part 2 (`C.Encode`/`C.Decode`) into
  `HQC-PKE.{Keygen,Encrypt,Decrypt}` and the salted-FO-transform
  `HQC-KEM.{Keygen,Encaps,Decaps}` (spec §3.5/§3.6 — note this is the
  updated `SFO^L_m` transform with implicit rejection, not the older
  `FO^L`; see the spec's 2025/08/22 and 2023/04/30 changelog entries).
  Verify byte-exact against `kats/ref/hqc-{1,3,5}/PQCkemKAT_*.rsp` (all
  100 vectors per parameter set) using `Prng` as the KAT DRBG (see "Spec
  version" above — no AES needed). Tier: **Sonnet** for the composition/
  wire-format work, contingent on Part 2 already being correct; the
  wire-format parsing itself (`ekKEM`/`dkKEM`/`cKEM` byte layouts) is
  mechanical struct-packing per spec §3.5/§4.2 and this module's already-
  verified byte sizes (params.zig).
