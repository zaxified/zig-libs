# falcon — SPEC

Falcon-512 and Falcon-1024 verification + codecs (COMPLETE, KAT-verified);
keygen + sign (SCAFFOLD — structure and API real, the hard math stubbed —
see "Keygen + sign scaffold" below). See [README.md](README.md) for purpose
and API.

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

- **No signer, deliberately.** ffSampling (LDL* tree over the FFT embedding
  + the discrete Gaussian sampler) has the property that an incorrect
  sampler still emits signatures that pass verification while statistically
  leaking the trapdoor basis. It ships only when it can ship KAT-exact
  against the deterministic (seeded-DRBG) sign vectors.
- Verification and public-key handling touch public data only, so no
  constant-time claims are made or needed for the implemented surface.
  Secret-key *decode* is not constant-time — treat `SecretKey.fromBytes` as
  a tooling/inspection path, not a production signing path (there is none).
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
  added for the keygen/sign scaffold below) came from the same download —
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

## Keygen + sign scaffold

Structure, key/tree types, KAT harness, and public API
(`generateKeyPair`/`signRandomized`/`signDeterministic`, `_1024`-suffixed
too, same `Params(logn)` factory as verify) are real and compile; the hard
math is `@panic("TODO(fable/core): ...")` stubbed. Grep the module for that
string, or see `root.zig`'s module doc comment, for the current list.

- **Reused as-is** (no new code needed): `poly.Ring.computePublic` (h =
  g·f⁻¹ mod q — keygen's public-key step is IDENTICAL to what
  `SecretKey.publicKey()` already does for decode), `codec.hashToPoint`,
  `codec.compEncode` (signature compression), the existing NTT. New but
  NOT hard: `codec.trimI8Encode` (secret-key encode, the missing inverse of
  the existing `trimI8Decode`), `keygen.zig` (glue: sample → solve → derive
  h → build tree → pack), `sign.zig` (glue: hash → sample → norm-check
  retry loop → compress; plus `ShakePrng`, a SHAKE256-seeded
  `std.Random` for deterministic/KAT signing).
- **Stubbed** (the four genuinely hard pieces, each its own file):
  - `ntru.zig` `Ntru(Ring).generate` — NTRUGen (§3.8.1 Algorithm 5) +
    NTRUSolve (§3.8.2 Algorithm 6): sample small (f,g), solve
    f·G − g·F = q via the number-field tower + Babai reduction. Needs a
    big-integer/exact-rational polynomial layer this module doesn't have.
  - `fft.zig` `Fft(Ring).fft`/`ifft` — the floating-point FFT (§3.4
    Algorithms 1/2) the sampler runs in; a DIFFERENT transform from
    `poly.zig`'s exact integer NTT, net-new.
  - `ffsampling.zig` `buildTree` (ffLDL, §3.8.3 Algorithm 9) +
    `sampleSignature` (ffSampling, §3.9.1 Algorithm 11), plus their
    `splitFft`/`mergeFft` helpers (§3.8.3 Algorithms 7/8) — the LDL* tree
    over the FFT embedding and the fast-Fourier nearest-plane recursion.
  - `gaussian.zig` `samplerZ` — SamplerZ (§3.9.2 Algorithms 12/13:
    BaseSampler + ApproxExp + BerExp). **THE side-channel-critical
    primitive**: an incorrect-but-plausible sampler here still produces
    signatures that PASS `root.zig`'s verification while statistically
    leaking the secret basis — functional correctness (even matching the
    spec's own standalone SamplerZ test vectors) is necessary but NOT
    sufficient; it needs a constant-time implementation and a dedicated
    side-channel audit, gated separately from the rest of the signer.
- **KAT harness**: `kat_vectors.zig`'s existing 5-per-degree vectors
  (counts 0/1/2/3/57) now also carry `seed` (the 48-byte NIST-KAT DRBG
  seed), re-extracted from the same SHA-256-verified `falcon-round3.zip`
  mirror the rest of the vectors were pulled from — see that file's module
  doc comment for the full provenance chain and the seed/PRNG-layer
  distinction. `keygen_sign_test.zig` is written against the FINAL keygen/
  sign API and `return error.SkipZigTest`s immediately before each call
  that would reach a stub, so it documents exactly what becomes a real
  byte-exact KAT check once the stubs are filled in, without failing
  `zig build test-falcon` today.
- FIPS 206 (FN-DSA) rebase once final — applies to verify+codecs too, not
  just this scaffold.
