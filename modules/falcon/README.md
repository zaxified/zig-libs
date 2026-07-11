# falcon

Falcon-512 (FN-DSA, the NIST post-quantum lattice signature scheme: NTRU
lattices + fast-Fourier trapdoor sampling) in pure Zig over `std.crypto`'s
SHAKE256. Together with `std.crypto`'s ML-DSA and this repo's `slhdsa`, this
completes local coverage of the NIST PQ signature trio.

**What is implemented — and NIST-KAT-verified byte-exactly — is signature
VERIFICATION plus every key/signature codec**: public-key decode/encode
(897 B, 14-bit packed h), secret-key decode (1281 B trimmed f/g/F) with
h = g·f⁻¹ mod q consistency recomputation, the canonical compressed
signature codec (decode + byte-exact re-encode), SHAKE256 hash-to-point,
the negacyclic NTT over Z_q[x]/(x⁵¹²+1) with q = 12289, and the
‖(s1, s2)‖² ≤ ⌊β²⌋ = 34034726 short-vector check.

**Key generation and signing are NOT implemented** (reserved): keygen needs
the NTRUSolve big-integer tower and signing needs the ffSampling trapdoor
Gaussian sampler, where a subtly wrong sampler still produces signatures
that *verify* while leaking the private key — that half only ships when it
can ship KAT-exact. Also out of scope: Falcon-1024, the padded/CT signature
formats (the compressed format the KATs use is implemented), and
constant-time hardening (verification handles public data only).

The KAT oracle is the official **NIST Round-3** `falcon512-KAT.rsp` (FIPS
206 / FN-DSA is still a draft standard; Round-3 Falcon is the stable
interop target — e.g. what PQClean and liboqs implement).

## Use

```zig
const falcon = @import("falcon");

// Decode a public key (897 bytes, 0x09 header).
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
```

## Verify

```
zig build test-falcon                          # Debug
zig build test-falcon -Doptimize=ReleaseFast
```

Runs the NIST Round-3 KATs (every embedded vector must open + verify, the
compressed signature and public key must re-encode byte-exactly, sk must
reproduce pk) plus tamper-rejection, NTT-vs-schoolbook, and codec
canonicality tests.

Provenance: clean-room from the Falcon Round-3 specification; the reference
implementation is a wire-format design reference + KAT oracle only — see
the `falcon` entry in the repo-root `NOTICE` and SPEC.md.
