# falcon — SPEC

Falcon-512 and Falcon-1024, COMPLETE: verification + codecs, signing, and
key generation, all NIST-KAT-verified byte-exactly (see "Keygen + sign"
below for the signer/keygen internals and the constant-time caveat). See
[README.md](README.md) for purpose and API.

## Design

- **Source of truth**: the Falcon Round-3 specification (falcon-sign.info).
  FIPS 206 (FN-DSA) is still a draft, so the stable Round-3 wire formats and
  KATs are the target; when FIPS 206 finalizes, expect a header-byte /
  domain-separation revision, not an NTT/math revision.
- **Degree-generic**: one implementation parameterized by `logn` serves both
  parameter sets. `poly.Ring(logn)` builds the ring/NTT, `codec.Codec(Ring)`
  the wire encodings, and `root.zig`'s internal `Params(logn, ⌊β²⌋)` the
  key types + verify. Falcon-512 = `Ring(9)`, Falcon-1024 = `Ring(10)`; the
  Falcon-512 flat API (`PublicKey`, `verify`, `poly.n`, …) is retained
  unchanged as aliases of the logn = 9 instantiation, and Falcon-1024 is
  exposed via `_1024`-suffixed names (`PublicKey1024`, `sig_bound_1024`, …).
- **Ring arithmetic** (`poly.zig`): Z_q[x]/(xⁿ+1), n ∈ {512, 1024},
  q = 12289. Iterative Cooley-Tukey forward / Gentleman-Sande inverse
  negacyclic NTT; twiddles `psi^bitrev(k)` are comptime-generated per degree
  from a comptime generator search (psi = g^((q−1)/2n), asserted psiⁿ = −1).
  Plain `% q` u32 arithmetic — no Montgomery form; q < 2¹⁴ keeps every
  product far below 2³². The NTT is cross-checked in tests against a
  schoolbook negacyclic convolution at both degrees.
- **Codecs** (`codec.zig`): mirror the spec's §3.11 encodings with all
  canonicality rules enforced on decode — modq coefficients ≥ q rejected,
  nonzero padding bits rejected, trimmed-i8 −2^(bits−1) rejected,
  compressed "-0" rejected, |s2 coefficient| ≤ 2047, and the signature
  field must be consumed exactly (no trailing bytes). The trimmed-i8 f/g
  width is per-degree (6 bits at n = 512, 5 bits at n = 1024; F is 8 bits
  either way). Encoders are byte-canonical, KAT-proven by re-encoding the
  vectors' own bytes.
- **Verification** (`root.zig`): c = SHAKE256-hash-to-point(nonce ‖ msg);
  −s1 = s2·h − c (one NTT of s2, pointwise mul with the cached NTT(h), one
  inverse NTT), coefficients normalized to [−q/2, q/2]; accept iff
  ‖(s1, s2)‖² ≤ ⌊β²⌋, summed exactly in u64 (no saturation needed: worst
  case < 2³⁶). ⌊β²⌋ = 34034726 for logn = 9 and 70265242 for logn = 10 —
  both taken from the Round-3 reference implementation's `common.c`
  `l2bound` table (index = logn): `{0, 101498, 208714, 428865, 892039,
  1852696, 3842630, 7959734, 16468416, 34034726, 70265242}`
  (falcon-sign.info/impl/common.c.html), the entries the spec marks as
  "inclusive … equal to floor(beta^2)".
- **Secret keys**: decode-only (f, g, F; G is not stored in the encoding and
  nothing here needs it). `publicKey()` recomputes h = g·f⁻¹ mod q in the
  NTT domain (pointwise Fermat inversion), erroring on non-invertible f.

## Threat model / limits

- **Signer correctness is KAT-pinned** precisely because ffSampling + the
  discrete Gaussian sampler have the property that an incorrect sampler
  still emits signatures that pass verification while statistically leaking
  the trapdoor basis; both are byte-exact against the seeded-DRBG sign
  vectors. **Constant-time status**: `gaussian.samplerZ` reproduces the
  reference's constant-time branch/table structure, and the underlying `fpr`
  arithmetic is the reference's branchless **integer emulation** of binary64
  (`fpr.zig`, `falcon512int` FALCON_FPEMU) — every add/sub/mul/div/sqrt and
  float→int conversion is a fixed sequence of integer mul/shift/select with
  no data-dependent branch, table index, or variable-latency FP instruction.
  This eliminates the earlier native-`f64` timing leak: Falcon's signing hot
  path runs division and sqrt on the SECRET-derived Gram matrix
  (`fft.polyLdlFft`, `ffsampling` leaf sqrt), and hardware `divsd`/`sqrtsd`
  have operand-dependent latency, so native f64 there was a timing side
  channel on the signing key. **Re-verified 2026-08-05** via a one-time
  `objdump` audit (methodology per `lockfree/SPEC.md`'s disassembly-based
  lowering check): `zig test src/root.zig -O ReleaseFast --test-no-exec
  -femit-bin=…` (falcon has zero external deps, so this compiles standalone),
  then `objdump -d --no-show-raw-insn` over the WHOLE resulting binary,
  grepped for every scalar AND AVX-encoded (`v`-prefixed) floating-point
  compute mnemonic (`{,v}{add,sub,mul,div,sqrt,round,ucomis,comis,cvtsi2s,
  cvts2si}{sd,ss,pd,ps}` and friends). Result: every hit is confined to
  exactly two functions, `fpr.test."integer emulation matches native
  IEEE-754 RNE bit-for-bit on random normal doubles"` and `fpr.test."integer
  emulation: of/rint/floor/trunc agree with native conversions"` — the two
  tests that INTENTIONALLY cross-check the integer emulation against real
  hardware FP, exactly as documented below. No keygen or signing function
  (`fpr.add`/`sign.Signer.signWithRng`/`ffsampling.sampleSignature`/
  `gaussian.samplerZ`/`ntru.solveNtru` and everything they inline) contains
  any such instruction. This corrects the previous, unsubstantiated phrasing
  here ("the only FP in a linked binary is dead `compiler_rt` transcendental
  code") — the FP that *is* present is live, intentional, test-only code, not
  dead `compiler_rt`; the substantive claim (the signing/keygen path itself
  emits none) holds and is now machine-verified rather than asserted. Scope
  of what this proves: only that no native-latency-variable FP instruction
  reaches the compiled artifact — it says nothing about `gaussian0`/`berExp`/
  `sampler`'s branch- or table-index structure, which remains covered by the
  unchanged "Remaining gate" below.
  The `fpr` emulation flushes subnormal *results* to zero, as the reference
  does; Falcon's signer never enters the subnormal regime (byte-exact KATs
  are the evidence), and the 50k-random-double cross-check tests confine
  operands to the normal range where flush-to-zero and native f64 agree
  bit-for-bit. **CT tax**: integer bit-by-bit div/sqrt make signing ~5x
  slower than native f64 (host-dependent; the writeup cites ~12.5x on a
  faster host with less fixed RNG/hash overhead) — accepted, and the
  security-correct default for a signing key. **Backend**: the module is
  CT-only; a native-`f64` fast-path (like the reference's separate `float`
  build variant) is intentionally NOT exposed as an in-file toggle, to avoid
  a footgun that could silently reopen the leak — add it as a separate module
  variant if a fast-path, non-adversarial-timing consumer ever appears.
  **Remaining gate**: no machine-checked side-channel verification
  (dudect/ctgrind/binsec) has been run on the compiled artifact — an
  out-of-toolchain dudect run before production signing remains the honest
  ask. **Why this module has no in-repo ctgrind harness, and should not get
  one.** The repo does now have a valgrind lane — `scripts/ctgrind.sh`,
  `zig build check-ctgrind` and `scripts/ctgrind-expected.tsv` — so "there is
  no lane" is no longer the reason. The reason is the sampler itself.
  `gaussian0` is branchless over the full RCDT table, but `sampler`'s reject
  loop iterates a *value-dependent* number of times and `berExp` keeps one
  data-dependent early break, both copied deliberately from the reference
  (see `src/gaussian.zig`'s header): the constant-time argument there is
  Bernoulli decorrelation, not a fixed trip count. ctgrind measures exactly
  what those two constructs do — branch on tainted data — so an in-repo row
  for `falcon` would be a permanent red that measures the reference design
  rather than a defect, and pinning it green would require excluding the one
  primitive the whole gate exists to watch. A red that measures nothing is
  worse than no row. Keygen (`ntru.zig`) likewise preserves the
  reference's structure and now shares the integer `fpr`; it runs once per
  key, so its side-channel exposure is far smaller than the signer's.
- Verification and public-key handling touch public data only, so no
  constant-time claims are made or needed for that surface. Secret-key
  *decode* is not constant-time — treat `SecretKey.fromBytes` as a
  tooling/inspection path.
- `openNistSignedMessage` implements the NIST-API envelope used by the KATs;
  it returns a sub-slice of the caller's buffer (no copy). The detached
  `PublicKey.verify` is the intended production entry point.
- Verify is vartime hash-to-point (like the reference's default); the
  constant-time hash-to-point variant only matters for exotic
  nonce-known/signature-hidden scenarios and is out of scope.

## Verification

- KAT oracles from the official NIST Round-3 submission package
  (`falcon-round3.zip`, falcon-sign.info):
  - `falcon512-KAT.rsp`, SHA-256 =
    `dd75c946fdedef4ec46a2bee7e10c65c9126f1a839b9ced6921fd45f7354b5cd`;
  - `falcon1024-KAT.rsp`, SHA-256 =
    `036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d`.

  For each set, vectors count ∈ {0, 1, 2, 3, 57} are embedded in
  `src/kat_vectors.zig` (msg/pk/sk/sm/seed; count 57 covers a ~1.9 KiB
  message). The 512 .rsp SHA-256 matches this module's original citation,
  confirming the mirror is bit-identical to the official package; both
  files were parsed from the same tree. `seed` (the NIST-KAT DRBG input,
  added for the keygen/sign section below) came from the same download —
  see `kat_vectors.zig`'s module doc comment for the full chain.
- Per vector: sm opens + verifies; opened message equals the vector's msg;
  compressed signature re-encodes byte-exactly; pk re-encodes byte-exactly;
  sk decodes and reproduces pk via h = g·f⁻¹. Falcon-512 uses the flat API,
  Falcon-1024 the `_1024` API — both against their own .rsp.
- Negative: tampered message / nonce / signature bytes, wrong header bytes
  (incl. cross-degree headers), truncated envelope, nonsense length field,
  cross-vector pk — all rejected, for both parameter sets.
- Both `zig build test-falcon` (Debug) and `-Doptimize=ReleaseFast` green;
  every test block on disk is executed (dark-tests rule).

## Keygen + sign

Both implemented, byte-exact against the NIST Round-3 KATs at both degrees.
The internals are ports of the MIT-licensed Round-3 reference
implementation (attribution in this directory's `NOTICE`); byte-exactness is the point —
it pins the trapdoor sampler and keygen sampling, whose failure mode is
"verifies fine, leaks the key".

- **Reused as-is**: `poly.Ring.computePublic` (h = g·f⁻¹ mod q),
  `codec.hashToPoint`, `codec.compEncode`/`trimI8Encode`, the existing NTT.
  Glue: `keygen.zig` (sample → solve → derive h → pack), `sign.zig` (hash →
  sample → norm-check retry loop → compress; plus `ShakePrng`, a
  SHAKE256-seeded `std.Random`).
- **The hard pieces** (each its own file):
  - `fpr.zig` — the reference's branchless **integer emulation** of binary64
    (`falcon512int` FALCON_FPEMU): add/sub/mul/div/sqrt + rint/floor/trunc/
    expm_p63 are pure u64/u32 arithmetic with exact IEEE round-to-nearest-
    even, carried in `f64` bit patterns via `@bitCast`. Constant-time (no
    native FP, no data-dependent branch); byte-exact vs the reference. Two
    tests cross-check every op against the hardware FPU on 50k random normal
    doubles (the regime Falcon uses), where correctly-rounded native f64 and
    the emulation must agree bit-for-bit.
  - `fft.zig` — the floating-point FFT (§3.4) in the reference's flat
    layout, plus the `poly_*_fft` helpers (signer + keygen Babai).
  - `gaussian.zig` — the ChaCha20 signer PRNG (reference `rng.c` layout)
    and SamplerZ (§3.9.2: gaussian0 RCDT walk + BerExp). **THE
    side-channel-critical primitive** — structure matches the reference's
    constant-time discipline; no machine-checked side-channel audit yet
    (see Threat model above).
  - `ffsampling.zig` — `ffSampling_fft_dyntree`/`do_sign_dyn` semantics:
    the Gram matrix + LDL* decomposition is built dynamically per
    signature, exactly like the `crypto_sign` path that generated the KATs
    (not the expanded-key variant).
  - `ntru.zig` — NTRUGen (§3.8.1: `mkgauss` keygen Gaussian + full
    acceptance loop) and NTRUSolve (§3.8.2: field-norm descent to degree 1,
    extended binary GCD over 31-bit-limb big integers, RNS/CRT
    reconstruction mod ~2³¹ primes, FP-FFT-guided Babai reduction with the
    reference's exact scale schedule). The reference's 522-entry PRIMES
    table is regenerated at runtime from its definition (largest primes
    < 2³¹ ≡ 1 mod 2048, descending; CRT coefficient per definition; NTT
    root choice is value-irrelevant) and cross-checked against the
    reference table's own (p, s) values in a test.
- **KAT coverage**: `kat_sign_test.zig` (sign-side: NIST AES-256-CTR-DRBG
  replay → byte-exact nonce + compressed signature, sk decoded from the
  vector) and `keygen_sign_test.zig` (keygen-side: DRBG draw 1 → SHAKE256
  keygen RNG → byte-exact pk/sk; plus the full seed → keygen → sign → `sm`
  pipeline and a fresh-key sign → verify round trip). `ntru.zig` also
  KAT-pins NTRUSolve in isolation: solving from the vectors' own (f, g)
  reproduces the sk's F byte-exactly at both degrees.
- No deterministic signing mode: the former `signDeterministic` (single
  SHAKE stream seeded from the caller's seed alone) reused the 40-byte
  salt — and the Gaussian sampling tape — across every message signed
  under one seed, voiding the GPV per-signature-independence argument;
  it was removed rather than derandomized because Falcon specifies no
  deterministic mode (no anchor for a homemade one) and deterministic
  lattice signing invites fault-differential/trace-averaging attacks —
  see the decision comment in `root.zig`. Reproducible signing for tests
  = `sign.ShakePrng` + `sign.Signer.signWithRng` (the KAT tests replay
  the NIST DRBG's two separate draws through that seam explicitly).
- FIPS 206 (FN-DSA) rebase once final — applies to the whole module.

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** official NIST Round-3 falcon512/1024-KAT.rsp files, byte-exact
