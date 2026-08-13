# falcon

Falcon-512 **and Falcon-1024** (FN-DSA, the NIST post-quantum lattice
signature scheme: NTRU lattices + fast-Fourier trapdoor sampling) in pure
Zig over `std.crypto`'s SHAKE256. Together with `std.crypto`'s ML-DSA and
this repo's `slhdsa`, this completes local coverage of the NIST PQ
signature trio.

**What is implemented — and NIST-KAT-verified byte-exactly, for both
parameter sets — is signature VERIFICATION plus every key/signature
codec**: public-key decode/encode (897 B / 1793 B, 14-bit packed h),
secret-key decode (1281 B / 2305 B trimmed f/g/F) with h = g·f⁻¹ mod q
consistency recomputation, the canonical compressed signature codec
(decode + byte-exact re-encode), SHAKE256 hash-to-point, the negacyclic
NTT over Z_q[x]/(xⁿ+1) with q = 12289 (n = 512 or 1024), and the
‖(s1, s2)‖² ≤ ⌊β²⌋ short-vector check (34034726 for n = 512, 70265242 for
n = 1024). A single degree-generic implementation (`poly.Ring(logn)` /
`codec.Codec(Ring)`) serves both sets; the Falcon-512 flat API is retained
unchanged and Falcon-1024 gets `_1024`-suffixed entry points.

**Key generation and signing are implemented and NIST-KAT-verified
byte-exactly too** (both parameter sets): NTRUGen/NTRUSolve (keygen's
Gaussian sampling + acceptance loop, and the tower-of-number-fields
big-integer solver with FP-FFT-guided Babai reduction, `ntru.zig`), the
strict-float `fpr` layer + FFT, the dynamic-tree ffSampling trapdoor
recursion, and SamplerZ (the ChaCha20-fed discrete Gaussian sampler).
`keygen_sign_test.zig` reproduces seed → pk/sk and the full
seed → keygen → sign → `sm` pipeline bit-for-bit against the NIST DRBG
replay. **Constant-time status**: the `fpr` layer is the reference's
branchless **integer emulation** of binary64 (`fpr.zig`), so the signing
hot path runs NO variable-latency FP instruction (`divsd`/`sqrtsd`/`mulsd`)
on the secret-derived Gram matrix — the earlier native-`f64` timing leak on
the signing key is closed (a whole-binary `objdump` audit, re-run
2026-08-05, confirms zero scalar/AVX FP compute instructions reach any
keygen/signing function — see SPEC.md's Threat model section for the
methodology and its scope). This costs ~5x (host-dependent) on signing vs
native f64; that CT tax is accepted and is the security-correct default.
`gaussian.samplerZ` reproduces the reference's constant-time branch/table
structure, whose only secret-structured branches are the documented BerExp
lazy-break + norm-bound rejection retry. **Remaining gate**: no
machine-checked side-channel verification (dudect/ctgrind/binsec) has been
run on the compiled artifact — a subtly leaky sampler still produces
signatures that *verify*, so run one before production signing (see
`gaussian.zig`'s module doc). Out of scope: the padded/CT signature format
(the compressed format the KATs use is implemented).

The KAT oracle is the official **NIST Round-3** `falcon512-KAT.rsp` and
`falcon1024-KAT.rsp` (FIPS 206 / FN-DSA is still a draft standard; Round-3
Falcon is the stable interop target — e.g. what PQClean and liboqs
implement).

## Use

```zig
const std = @import("std");
const falcon = @import("falcon");

// Falcon-512: decode a public key (897 bytes, 0x09 header).
const pk = try falcon.PublicKey.fromBytes(pk_bytes[0..897]);

// Verify a detached compressed signature: 40-byte nonce + signature field
// (0x29 header byte followed by the compressed s2, exactly).
try pk.verify(message, nonce, sig_field); // error.InvalidSignature | error.SignatureVerificationFailed

// Or open a NIST-API signed message (the KAT `sm` envelope:
// 2-byte BE sig length || 40-byte nonce || message || signature field).
const msg = try falcon.openNistSignedMessage(&pk, sm);

// Secret-key decode + consistency check against the public key.
const sk = try falcon.SecretKey.fromBytes(sk_bytes[0..1281]);
const pk2 = try sk.publicKey(); // h = g * f^-1 mod q

// Falcon-1024: identical shape, `_1024`-suffixed types/entry points.
const pk10 = try falcon.PublicKey1024.fromBytes(pk_bytes[0..1793]); // 0x0a header
try pk10.verify(message, nonce, sig_field); // 0x2a header byte on sig_field
const msg10 = try falcon.openNistSignedMessage1024(&pk10, sm);

// Keygen + sign (see the constant-time caveat above before production
// signing). `rng` is any std.Random backed by a CSPRNG.
const kp = try falcon.generateKeyPair(rng);
var nonce_buf: [falcon.nonce_length]u8 = undefined;
var sig_buf: [falcon.max_sig_field_length]u8 = undefined;
const len = try falcon.signRandomized(&kp.signing_key, message, rng, &nonce_buf, &sig_buf);
try kp.public_key.verify(message, &nonce_buf, sig_buf[0..len]);
// Falcon-1024: falcon.generateKeyPair1024 / signRandomized1024, same shape.
```

## Verify

```
zig build test-falcon                          # Debug
zig build test-falcon -Doptimize=ReleaseFast
```

Runs the NIST Round-3 KATs for both Falcon-512 and Falcon-1024 across the
whole scheme: verify-side (every embedded vector must open + verify, the
compressed signature and public key must re-encode byte-exactly, sk must
reproduce pk, tamper-rejection, NTT-vs-schoolbook, codec canonicality),
sign-side (`kat_sign_test.zig`: byte-exact nonce + compressed signature via
NIST-DRBG replay), and keygen-side (`keygen_sign_test.zig`: byte-exact
seed → pk/sk, the full seed → keygen → sign → `sm` pipeline, an NTRUSolve-
only F reproduction from KAT (f, g), and a fresh-key sign → verify round
trip).

Provenance: verification + codecs are clean-room from the Falcon Round-3
specification ("Falcon: Fast-Fourier Lattice-based Compact Signatures over
NTRU", falcon-sign.info — the NIST PQC Round-3 submission document; FIPS 206 /
FN-DSA is still a draft). The Round-3 reference implementation (MIT, Copyright
(c) 2017-2019 Falcon Project, Thomas Pornin) was consulted for those parts only
to pin wire-format/behavior facts (the NIST-API signed-message envelope,
key/signature header bytes, codec canonicality rules, the `l2bound` norm table);
the signer and keygen internals (`fpr`/`fft`/`gaussian`/`ffsampling`/`ntru`) are
a **port** of that same MIT reference, required for byte-exact KAT
reproduction — the required attribution ships as [NOTICE](NOTICE) in this
directory and lists the ported files; see also SPEC.md. The submission package's
`falcon512-KAT.rsp` / `falcon1024-KAT.rsp` vectors are used purely as the test
oracle (SHA-256 of each `.rsp` recorded in SPEC.md); each embedded vector's
`seed` field was re-extracted from the same SHA-256-verified mirror. The
Falcon-1024 squared-norm acceptance bound (⌊β²⌋ = 70265242) is sourced from the
reference `common.c` `l2bound` table — see SPEC.md.