# hqc — SPEC

A multi-part HQC arc, now **complete**. Part 1 (ring + PRNG foundation) is
done. Part 2 (concatenated Reed-Muller/Reed-Solomon codec) is complete:
encode is byte-exact-KAT'd and both decoders are implemented (exact ports
of the v5.0.0 reference) with decode-correctness tests. Part 3 (PKE + FO
KEM composition) is complete: `Hqc128`/`Hqc192`/`Hqc256` are a usable KEM,
byte-exact against the official NIST KAT (see "Part 3" and "Arc plan"
below). See [README.md](README.md) for purpose and API.

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
  (fetched via `curl`, not a paraphrasing tool — see
  `kat_vectors_kem.zig`) — the `.rsp` files ship count=0..99
  keypair/ciphertext/shared-secret vectors each (standard NIST `.rsp`
  format: `seed`/`pk`/`sk`/`ct`/`ss`); this module pins the first 3
  (`count`=0,1,2) per parameter set, enough for byte-exact confidence
  without embedding the full 100-vector/1.8-5.8 MB-per-set files (see
  `kat_vectors_kem.zig`'s module doc). The 48-byte `seed` field feeds
  HQC's own `Prng` (see "PRNG" below) directly — **no AES-256-CTR-DRBG is
  needed**, confirmed by reading `packaging/utils/helpers/main_kat.c`
  (the actual `PQCgenKAT_kem.c` harness shipped in this release): it
  calls `prng_init(entropy_input, NULL, 48, 0)` then
  `prng_get_bytes(seed, 48)` per vector, and re-derives the same
  per-vector `seed` via a second `prng_init(seed, NULL, 48, 0)` before
  `crypto_kem_keypair`/`_enc`. This is a deliberate departure from the
  classic NIST harness (which normally wraps AES-256-CTR-DRBG) — HQC's
  own release replaces it with SHAKE256, which `std.crypto` already has.
  `kem_kat_test.zig` reproduces this exactly: one continuing `Prng`
  stream feeds `seed_kem` (32 B, for `keypair`) then `coins` (m || salt,
  for `encaps`), matching `crypto_kem_keypair` then `crypto_kem_enc`
  drawing off the same DRBG in sequence.

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
| `gf256.exp`/`log` tables | Numeric-KAT-pinned (self-derived) | `gf256.zig`: `generateTables` independently re-derives both tables from `poly` via the reference's own `gf_generate` recurrence; matches the transcribed `gf.h` tables byte-exact |
| `gf256.mul`/`square`/`inverse` | Algebraic + provably-equivalent | Field-axiom tests (associativity, distributivity, multiplicative inverse) plus the argument that GF(2^8) multiplication is representation-unique (see "Part 2" section below) — not a different-algorithm-vs-reference numeric pin, since this module doesn't port the reference's carryless-multiply algorithm at all |
| `reedsolomon.RS(p,g).encode` | Numeric-KAT-pinned | `code_kat_test.zig`: byte-exact vs. the reference's `reed_solomon_encode` for 4 message patterns × 3 parameter sets (`kat_vectors_code.zig`) |
| `reedmuller.RM(p).encodeBlock`/`encodeSymbol` | Numeric-KAT-pinned | `code_kat_test.zig`: byte-exact vs. the reference's `encode`+duplication for 8 byte values × 3 parameter sets |
| `code.Code(p,g).encode` | Numeric-KAT-pinned (hqc-128 full; hqc-192/256 zero-message only) | `code_kat_test.zig`: byte-exact vs. the reference's `code_encode`; full-codeword vectors for 3 message patterns on hqc-128, zero-message only on hqc-192/256 (see `kat_vectors_code.zig`'s coverage note) |
| `reedsolomon.RS(p,g).decode`, `reedmuller.RM(p).decodeSymbol` | Decode-correctness tested (all 3 sets) | `code_kat_test.zig` (gated by `gate.decoder_core_implemented = true`): zero-error round-trip `decode(encode(m)) == m`, at-capacity (exactly δ symbol errors) correction at both the concatenated-code and bare-RS layers, and exhaustive 256-value RM `decodeSymbol` — covering hqc-128 (PARAM_FFT=4 unrolled radix) and hqc-192/256 (PARAM_FFT=5 `radixBig`). Exact ports of the reference; not a fresh numeric intermediate-value pin (no such fixture ships for this layer) |
| `Pke(p,g).keygen`/`.encrypt`/`.decrypt` | Numeric-KAT-pinned (via `Kem`) | `kem_kat_test.zig`: `Kem.keypair`/`encaps`/`decaps` — which call these directly, unwrapped — reproduce the official NIST `.rsp` pk/sk/ct/ss byte-exact for all 3 parameter sets (first 3 `count`s each) |
| `Kem(p,g).keypair`/`.encaps`/`.decaps` | Numeric-KAT-pinned | `kem_kat_test.zig`: byte-exact pk/sk/ct/ss vs. `kat_vectors_kem.zig` (official NIST `.rsp`, first 3 `count`s × 3 parameter sets), plus `decaps` on the genuine ciphertext recovering the same `ss` — reproducing `main_kat.c`'s own internal self-check. Additionally: random-coins round-trip property tests and a decaps-failure/implicit-reject test (corrupted ciphertext → deterministic `J`-derived rejection value, ≠ real `ss`, no crash) |

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

**What Part 1 could NOT pin** (now closed by Part 3): end-to-end `.rsp`
keypair/ciphertext/shared-secret reproduction, since that requires the
full PKE (`gf2x.mul` composed with the Part-2 decoder) — see "Part 3"
section below for how `kem_kat_test.zig` closes this.

## Part 2 (RS/RM concatenated codec) — status

Part 2 adds `gf256.zig` (GF(2^8)), `reedsolomon.zig` (the outer [n1,k,delta]
code), `reedmuller.zig` (the inner duplicated RM(1,7) code), and `code.zig`
(their concatenation). **Encode is fully real and byte-exact-KAT'd; both
decode cores are now real implementations too** (Fable pass, exact ports of
the v5.0.0 reference), with `gate.decoder_core_implemented = true`
(`gate.zig`) — see `reedsolomon.zig`'s `RS(p,g).decode` and
`reedmuller.zig`'s `RM(p).decodeSymbol` doc comments for the full
step-by-step algorithm each satisfies (syndromes → constant-time
Berlekamp-Massey → Gao-Mateer additive-FFT root-finding → Forney, for RS;
expand-and-sum → fast Hadamard transform → find_peaks, for RM). The decode
cores are pinned by `code_kat_test.zig`'s correctness tests: zero-error
round-trip and at-capacity (exactly δ symbol errors) correction at both the
concatenated-code and bare-RS layers, plus exhaustive RM `decodeSymbol`,
across all three parameter sets — including hqc-192/256's PARAM_FFT=5
`radixBig` additive-FFT path.

**Reference source consulted**: same tag as Part 1, `v5.0.0`
(`gitlab.com/pqc-hqc/hqc`) — specifically `src/ref/gf.c`/`gf.h`,
`src/ref/reed_solomon.c`/`reed_solomon.h`, `src/ref/reed_muller.c`,
`src/common/reed_muller.h`, `src/common/fft.c`/`fft.h` (the additive-FFT
root-finder — note this file lives under `src/common/`, not `src/ref/`,
unlike its caller `reed_solomon.c`), `src/common/code.c`/`code.h`, and
`src/ref/data_structures.h` (`rm_codeword_t`). Fetched via the GitLab
raw-file endpoint and the repository-tree API (`per_page`/`recursive`),
not through any summarizing/paraphrasing tool, same care as Part 1's
`intermediates_values` fetch.

**Corrects an earlier (pre-fetch) note**: an earlier draft of this
document's "Arc plan" claimed the RS/RM composition needed "shortened-RS
index offsets (RS-S1/S2/S3 subtract 209/199/165 from the standard RS-1/2/3
tables)". Having now actually fetched and read the v5.0.0 reference
source, this does not match what's there — v5.0.0's `alpha_ij_pow` syndrome
tables and additive-FFT root-finder have no such offset constants; that
note appears to describe an older/different HQC draft and should be
treated as superseded by `reedsolomon.zig`'s `decode` doc comment (which
documents the six real decode steps as read directly from this tag's
source), not as additional truth to reconcile.

**KAT strategy for Part 2's real (encode) code**: no `.rsp`-style official
fixture covers the RS/RM/code layer in isolation (checked: this tag's
`kats/ref/hqc-*/intermediates_values` files only cover the PKE/KEM layer's
PRNG-derived values). Byte-exact vectors were instead obtained by
compiling and running the reference's own unmodified encode-side C files
locally (`gf.c`+`reed_solomon.c`+`reed_muller.c`+`code.c`+`fft.c`+
`crypto_memset.c`, `gcc -O0`, one build per parameter set's own
`parameters.h`) and transcribing stdout mechanically via a small Python
script (no hand transcription, no LLM-summarized hex) — see
`kat_vectors_code.zig`'s module doc for the full provenance and exactly
which vectors are pinned at full depth (hqc-128) vs. lighter depth
(hqc-192/256).

**GF(2^8) note**: this module's `mul` uses a discrete-log table lookup,
NOT the reference's carryless-multiply-then-reduce (`gf_carryless_mul` +
`gf_reduce`, a `pclmulqdq`-emulation for the reference's target hardware).
Both compute the same field product (GF(2^8) multiplication is uniquely
determined by the primitive polynomial + generator, not by the algorithm)
— confirmed in `gf256.zig`'s tests by independently re-deriving the
`exp`/`log` tables from the primitive polynomial via the reference's own
`gf_generate` recurrence and checking byte-exact agreement with the
transcribed tables, plus the standard field-axiom tests. This is the same
tradeoff Part 1's `gf2x.zig` made for its ring `mul` (schoolbook vs.
Toom-Cook/Karatsuba) — see that section above.

**Constant-time posture of the decoders**: the two decode cores
(`RS(p,g).decode`, `RM(p).decodeSymbol`) add **no new secret-dependent
branches or memory indices** — they port the reference's constant-time
structure directly: masked branch-free selects in Berlekamp-Massey
(`compute_elp`), a data-independent additive-FFT access pattern,
constant-access-pattern Forney bookkeeping (`compute_error_values`), and a
branch-free `find_peaks`. The **one** pre-existing, module-wide caveat is
that `gf256.mul`/`inverse` do their work through the `exp`/`log` tables,
i.e. **secret-indexed table loads** (a cache-timing side channel on the
field elements the decoder handles), whereas the reference's
`gf_carryless_mul`+`gf_reduce` is a table-free carryless multiply. This is
the Part-1 field-arithmetic tradeoff noted above, inherited unchanged by
Part 2; a follow-up could switch `gf256` to a constant-time carryless
multiply if machine-checked side-channel resistance is required (flagged as
follow-up, not blocking Part 2/3 correctness). As with Part 1, no
dudect/ctgrind machine verification has been run — the structural match to
the reference is by construction, not instrument-verified.

## Part 3 (PKE + FO KEM composition) — status

Part 3 adds `pke.zig` (the HQC public-key encryption scheme: `Pke(p,g).
keygen`/`.encrypt`/`.decrypt`) and `kem.zig` (the Fujisaki-Okamoto
implicit-rejection KEM transform over it: `Kem(p,g).keypair`/`.encaps`/
`.decaps`), plus `root.zig`'s `Hqc128`/`Hqc192`/`Hqc256` convenience
instantiations. **This is pure composition, confirmed not Fable-hard**:
every operation is direct wiring over Parts 1-2's already-real
primitives — `gf2x.Ring(n).{add,mul,truncate,fromBytes,toBytes}` for all
ring arithmetic, `prng`'s `Xof`/`Prng`/samplers/I·G·H·J hashes for every
randomness-derivation and hash step, `code.Code(p,g).{encode,decode}` for
the error-correcting layer. No new algorithm is introduced anywhere in
Part 3 — the same posture this repo's bn254 precompiles/Groth16
composition work carried (see zig_libs project memory). The only design
decisions Part 3 makes are (a) taking `seed`/`coins` as explicit caller-
supplied byte arrays rather than owning a stateful global PRNG (keeps the
module free of hidden state; the reference's `main_kat.c` harness still
gets reproduced exactly by driving `prng.Prng` manually in the KAT test —
see `kem_kat_test.zig`) and (b) reproducing the reference's
`vect_compare`-based constant-time mask trick for implicit rejection
bit-for-bit (`kem.zig`'s `vectCompare`) rather than a higher-level
`std.crypto.timing_safe` helper, to stay byte-and-structure-faithful to
the reference the same way every other primitive in this arc is.

**Byte layout, matched against the reference exactly** (`src/ref/hqc.c`,
`src/common/kem.c`, `src/ref/parsing.c`, `src/common/symmetric.c`, all
read directly):

- `ek_pke = seed_ek(32) ‖ s(⌈n/8⌉)`; `dk_pke = seed_dk(32)` **only** — `x`
  is generated during keygen but never serialized (decrypt only ever
  needs `y`, which is re-derived from `seed_dk` on every call, matching
  the reference's `hqc_dk_pke_from_string`). `ek_kem = ek_pke` verbatim;
  `dk_kem = ek_kem ‖ dk_pke ‖ sigma ‖ seed_kem`.
- Keygen's `(y, x)` are sampled off **one** `Xof(seed_dk)` context, y then
  x, chained (same load-bearing `Xof.getBytes` ordering dependency Part 1
  flagged for the ring-vector samplers). Encrypt's `(r2, e, r1)` — note
  this order, not `(r1, r2, e)` — are sampled off one `Xof(theta)`
  context, all three biased-sampler draws chained.
  `s = y·h + x`; `u = r2·h + r1`; `v = C.encode(m) ⊕ Truncate(s·r2 + e)`;
  decrypt recovers `m = C.decode(v ⊕ Truncate(u·y))` (XOR, since
  subtraction is addition over F2).
- KEM keygen: `(seed_pke, sigma) = Xof(seed_kem).getBytes(32) then
  .getBytes(securityBytes)`, chained on one Xof context.
- Encaps: `H_ek = H(ek)`; `(K, theta) = G(H_ek, m, salt)` (one SHA3-512
  call, first half `K`, second half `theta`); `ct = u ‖ v ‖ salt`;
  `ss = K`.
- Decaps: `m' = Pke.decrypt(dk_pke, c)`; `(K', theta') = G(H(ek), m',
  salt)`; re-encrypt to get `ct'`; the implicit-rejection value is
  `K_bar = J(H(ek), sigma, ct)` — **the ORIGINAL ciphertext bytes**, not
  the re-encrypted `ct'` — computed unconditionally (not just on
  mismatch, so its cost doesn't leak the outcome); final
  `ss = (ct' == ct) ? K' : K_bar`, selected via the reference's
  `vect_compare`+mask-subtraction trick (0/1 compare result, `-% 1` wraps
  0→0xFF/1→0x00, then `(K'[i] & mask) ^ (K_bar[i] & ~mask)` per byte) —
  not a source-level `if`.

**Reference source consulted** (same tag, `v5.0.0`): `src/ref/hqc.c`
(`hqc_pke_keygen`/`_encrypt`/`_decrypt`), `src/ref/parsing.c`
(`hqc_ek_pke_from_string`/`hqc_dk_pke_from_string`/
`hqc_c_kem_to_string`/`_from_string`), `src/common/kem.c`
(`crypto_kem_keypair`/`_enc`/`_dec`), `src/common/symmetric.c` (hash/PRNG
domain wiring, already Part 1 territory), `src/ref/vector.c`
(`vect_compare`, `vect_truncate` — already Part 1 territory),
`packaging/utils/helpers/main_kat.c` (the KAT harness's DRBG-seeding
sequence). Fetched via the GitLab raw-file endpoint, same care as Parts
1-2 (no summarizing/paraphrasing tool).

**KAT strategy for Part 3**: the official `kats/ref/hqc-{1,3,5}/
PQCkemKAT_{2321,4602,7333}.rsp` files (100 vectors each, standard NIST
`seed`/`pk`/`sk`/`ct`/`ss` format) were fetched via `curl` and parsed by a
small Python script (no hand transcription, no LLM-summarized hex); the
first 3 `count`s per parameter set are embedded in `kat_vectors_kem.zig`.
`kem_kat_test.zig` seeds `prng.Prng` from each vector's 48-byte `seed`
exactly as `main_kat.c` does, draws `seed_kem` then `coins` off that one
continuing stream, and asserts `keypair`'s `(ek, dk)`, `encaps`'s
`(ct, ss)`, and `decaps(dk, ct)`'s recovered `ss` are all byte-exact
against the vector — the definitive end-to-end check for the whole arc.
Also present: a random-coins round-trip property test (all three
parameter sets) and a decaps-failure/implicit-reject test (corrupted
ciphertext → decaps returns the deterministic `J`-derived rejection
value, not a crash, and different from the real shared secret).

## Arc plan

- **Part 1** — ring + PRNG foundation. Tier: Sonnet (mechanical
  constant-structure bit arithmetic + exact PRNG-construction matching).
  **No part of Part 1 is genuinely Fable-hard** — the closest candidate,
  `gf2x.mul`'s constant-time structure, is a known, mechanical
  transformation (branch → mask) of an already-fully-specified reference
  algorithm, not an open algorithmic problem.
- **Part 2 (this module) — concatenated Reed-Muller/Reed-Solomon codec**
  (spec §3.4): the [n1n2, k] code C, built by concatenating an
  [n1,k,delta] Reed-Solomon code over GF(2^8) (outer) with a duplicated
  first-order Reed-Muller code RM(1,7) = [128,8,64] (inner, replicated 3×
  for hqc-128 or 5× for hqc-192/256 — `params.rm_multiplicity`). Encode
  (both halves + the concatenation) is Sonnet-tier and DONE. **The two
  decoders are the genuinely Fable-hard core of the HQC arc and are now
  implemented** (Fable pass): RM decoding via the fast Hadamard transform
  (maximum-likelihood over the duplicated code, "Green machine" per spec
  §3.4.3) and RS decoding via a constant-time Berlekamp-Massey
  error-locator polynomial plus an *additive* FFT (Gao-Mateer, with
  Bernstein/Chou/Schwabe's radix optimizations, including the `radix_big`
  recursion for hqc-192/256's PARAM_FFT=5) for root-finding over GF(2⁸) —
  additive FFTs are a meaningfully harder primitive than the
  multiplicative NTTs this repo already has (falcon, bls12_381). Both are
  exact ports of the v5.0.0 reference (`reedsolomon.zig`/`reedmuller.zig`),
  with `gate.decoder_core_implemented = true` and decode-correctness KATs
  driving them across all three parameter sets. Tier: **Fable** (decode
  only; encode already shipped as Sonnet work, see "Part 2 status" above).
- **Part 3 — HQC-PKE + HQC-KEM, byte-exact vs NIST KAT. DONE.** Composed
  Part 1 (ring `mul`, samplers) with Part 2 (`C.Encode`/`C.Decode`) into
  `Pke(p,g).{keygen,encrypt,decrypt}` and the salted-FO-transform
  `Kem(p,g).{keypair,encaps,decaps}` (spec §3.5/§3.6 — this is the
  updated `SFO^L_m` transform with implicit rejection, not the older
  `FO^L`; see the spec's 2025/08/22 and 2023/04/30 changelog entries).
  Verified byte-exact against `kats/ref/hqc-{1,3,5}/PQCkemKAT_*.rsp`
  (first 3 counts per parameter set pinned; see "Part 3" section above)
  using `Prng` as the KAT DRBG (see "Spec version" above — no AES
  needed). Tier: **Sonnet**, confirmed — pure composition/wire-format
  work over Parts 1-2's already-real primitives, no new algorithm; the
  wire-format parsing itself (`ekKEM`/`dkKEM`/`cKEM` byte layouts) is
  mechanical struct-packing per spec §3.5/§4.2 and this module's already-
  verified byte sizes (params.zig). **The whole HQC arc is now complete
  and usable as a KEM** (`root.zig`'s `Hqc128`/`Hqc192`/`Hqc256`).
