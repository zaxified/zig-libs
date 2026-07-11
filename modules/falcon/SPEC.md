# falcon — SPEC

Falcon-512 verification + codecs; see [README.md](README.md) for purpose and API.

## Design

- **Source of truth**: the Falcon Round-3 specification (falcon-sign.info).
  FIPS 206 (FN-DSA) is still a draft, so the stable Round-3 wire formats and
  KATs are the target; when FIPS 206 finalizes, expect a header-byte /
  domain-separation revision, not an NTT/math revision.
- **Ring arithmetic** (`poly.zig`): Z_q[x]/(x⁵¹²+1), q = 12289. Iterative
  Cooley-Tukey forward / Gentleman-Sande inverse negacyclic NTT; twiddles
  `psi^bitrev9(k)` are comptime-generated from a comptime generator search
  (psi = g^((q−1)/1024), asserted psi⁵¹² = −1). Plain `% q` u32 arithmetic —
  no Montgomery form; q < 2¹⁴ keeps every product far below 2³². The NTT is
  cross-checked in tests against a schoolbook negacyclic convolution.
- **Codecs** (`codec.zig`): mirror the spec's §3.11 encodings with all
  canonicality rules enforced on decode — modq coefficients ≥ q rejected,
  nonzero padding bits rejected, trimmed-i8 −2^(bits−1) rejected,
  compressed "-0" rejected, |s2 coefficient| ≤ 2047, and the signature
  field must be consumed exactly (no trailing bytes). Encoders are
  byte-canonical, KAT-proven by re-encoding the vectors' own bytes.
- **Verification** (`root.zig`): c = SHAKE256-hash-to-point(nonce ‖ msg);
  −s1 = s2·h − c (one NTT of s2, pointwise mul with the cached NTT(h), one
  inverse NTT), coefficients normalized to [−q/2, q/2]; accept iff
  ‖(s1, s2)‖² ≤ 34034726 (the spec's ⌊β²⌋ for logn = 9), summed exactly in
  u64 (no saturation needed: worst case < 2³⁶).
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

- KAT oracle: `falcon512-KAT.rsp` from the official NIST Round-3 submission
  package (`falcon-round3.zip`, falcon-sign.info);
  SHA-256(falcon512-KAT.rsp) =
  `dd75c946fdedef4ec46a2bee7e10c65c9126f1a839b9ced6921fd45f7354b5cd`.
  Vectors count ∈ {0, 1, 2, 3, 57} embedded in `src/kat_vectors.zig`
  (msg/pk/sk/sm; count 57 covers a ~1.9 KiB message).
- Per vector: sm opens + verifies; opened message equals the vector's msg;
  compressed signature re-encodes byte-exactly; pk re-encodes byte-exactly;
  sk decodes and reproduces pk via h = g·f⁻¹.
- Negative: tampered message / nonce / signature bytes, wrong header bytes,
  truncated envelope, nonsense length field, cross-vector pk — all rejected.
- Both `zig build test-falcon` (Debug) and `-Doptimize=ReleaseFast` green;
  19 test blocks on disk = 19 executed (dark-tests rule).

## Backlog

- Keygen + sign (NTRUSolve; ffSampling + SamplerZ with the spec's RCDT/
  BerExp tables — the spec appendix ships SamplerZ test vectors to KAT the
  sampler in isolation; deterministic sign KATs need the NIST AES-CTR-DRBG).
- Falcon-1024 (parameterize n/logn; the codecs and NTT generalize directly).
- FIPS 206 (FN-DSA) rebase once final.
