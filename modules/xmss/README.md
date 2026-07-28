# xmss

XMSS — the eXtended Merkle Signature Scheme (RFC 8391): **stateful**
hash-based digital signatures, pure Zig over `std.crypto`'s SHA-256.
Post-quantum, conservative security (hash functions only), small keys,
~2.5 KB signatures — but the private key is a consumable: every signature
burns one one-time key, and reusing one breaks the scheme.

**Status: single-tree XMSS, SHA-256 suite (n = 32, w = 16, len = 67),
complete keygen/sign/verify.** All three REQUIRED RFC 8391 parameter sets
exported — `XmssSha2_10_256` / `_16_256` / `_20_256` (IANA OIDs 1/2/3) —
plus any height via `XmssSha2(h, oid)`. Byte-exact against the official
XMSS reference implementation (github.com/XMSS/xmss-reference, the code
linked from RFC 8391 §7): the F/H/H_msg/PRF primitives, full WOTS+
(pkGen/sign/pkFromSig), XMSS keygen + sign at test height h = 4, and
verification of two real reference-generated XMSS-SHA2_10_256 signatures
under the reference's public key — a genuine external (pk, msg, sig)
interop triple. See `src/kat_vectors.zig` for provenance.

| Set | h | #sigs | pk (wire) | signature |
|-----|----|-------|-----------|-----------|
| XMSS-SHA2_10_256 | 10 | 1 024 | 68 B | 2 500 B |
| XMSS-SHA2_16_256 | 16 | 65 536 | 68 B | 2 692 B |
| XMSS-SHA2_20_256 | 20 | 1 048 576 | 68 B | 2 820 B |

```zig
const xmss = @import("xmss");
const X = xmss.XmssSha2_10_256;

// Seeds from a CSPRNG — sk_seed and sk_prf secret, pub_seed public.
var kp = X.keyGen(sk_seed, sk_prf, pub_seed); // O(2^h) hashing, one-time

var sig: [X.signature_length]u8 = undefined;
try X.sign(&kp.sk, &sig, message); // advances kp.sk.idx — PERSIST sk first!

const ok = X.verify(kp.pk, message, &sig);
```

**STATEFUL-KEY HAZARD:** `sign` mutates `SecretKey.idx`. Persist the
updated key *before* releasing the signature; never sign from a restored
backup or from two copies of the key. If you cannot guarantee that, use
the stateless sibling module `slhdsa` instead. See SPEC.md.

**Not implemented:** XMSS^MT (multi-tree), SHA-512/SHAKE suites.

**Auth-path traversal is BDS (Buchmann–Dahmen–Schneider), not a naive
recompute:** `sign` emits the current leaf's auth path from `SecretKey.bds`
and advances it in ~O(h) hashing per signature (about verify cost), instead
of rebuilding the whole path in O(2^h) — cheap even at h = 20. An
out-of-band `idx` jump (index partitioning, a restored key) auto-resyncs
the BDS state in O(2^h) before that one signature, then stays O(h) again.
See SPEC.md for how this is validated (differential against a from-scratch
reference at every leaf for two heights, plus a dedicated resync test).

- **Model after:** RFC 8391 (public IRTF spec, clean-room); the XMSS
  reference implementation used only as a black-box KAT oracle (NOTICE).
  Fills a real std gap: Zig 0.16 `std.crypto` has no stateful hash-based
  signature (RFC 8391 XMSS / RFC 8554 LMS — the NIST SP 800-208 pair).
- **Deps:** none (std only — `std.crypto.hash.sha2.Sha256`).
- **Consumer:** SCADA firmware signing (IEC 62443-style code-signing
  chains standardize on SP 800-208 stateful HBS).
