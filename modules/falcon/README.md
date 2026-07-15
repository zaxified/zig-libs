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

**Key generation and signing are a SCAFFOLD, not a working implementation**:
the API shape (`generateKeyPair`/`signRandomized`/`signDeterministic`, both
degrees), key/tree types, and a KAT harness (`kat_vectors.zig`'s vectors now
carry each `seed`) are real and compile; the four genuinely hard pieces —
NTRUGen/NTRUSolve (keygen's big-integer tower), the floating-point FFT, the
ffSampling trapdoor recursion, and SamplerZ (the discrete Gaussian sampler
— side-channel-critical: a subtly wrong sampler still produces signatures
that *verify* while leaking the private key) — are `@panic("TODO(fable/
core): ...")` stubs. See `SPEC.md`'s "Keygen + sign scaffold" section for
the file-by-file breakdown. Also out of scope even once filled in: the
padded/CT signature format (the compressed format the KATs use is
implemented) and constant-time hardening beyond `gaussian.samplerZ` itself
(verification handles public data only and needs none).

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

// Keygen + sign: API shape is real, but PANICS today (see the SCAFFOLD
// note above — the hard math is stubbed).
const kp = try falcon.generateKeyPair(std.crypto.random);
var nonce_buf: [falcon.nonce_length]u8 = undefined;
var sig_buf: [falcon.max_sig_field_length]u8 = undefined;
const len = try falcon.signRandomized(&kp.signing_key, message, std.crypto.random, &nonce_buf, &sig_buf);
try kp.public_key.verify(message, &nonce_buf, sig_buf[0..len]);
```

## Verify

```
zig build test-falcon                          # Debug
zig build test-falcon -Doptimize=ReleaseFast
```

Runs the NIST Round-3 KATs for both Falcon-512 and Falcon-1024 (every
embedded vector must open + verify, the compressed signature and public key
must re-encode byte-exactly, sk must reproduce pk) plus tamper-rejection,
NTT-vs-schoolbook, and codec canonicality tests. `keygen_sign_test.zig`'s
4 keygen/sign KAT-harness tests currently report SKIPPED (not failed) —
each stops with `error.SkipZigTest` right before the call that would reach
a stub; see that file's module doc comment for exactly what they check
once keygen/sign are implemented.

Provenance: clean-room from the Falcon Round-3 specification; the reference
implementation is a wire-format design reference + KAT oracle only — see
the `falcon` entry in the repo-root `NOTICE` and SPEC.md. The Falcon-1024
squared-norm acceptance bound (⌊β²⌋ = 70265242) is sourced from the
reference `common.c` `l2bound` table — see SPEC.md.
