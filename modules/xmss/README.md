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
var kp: X.KeyPair = undefined;
X.keyGen(&kp, &sk_seed, &sk_prf, &pub_seed); // O(2^h) hashing, one-time; secrets by pointer

var sig: [X.signature_length]u8 = undefined;
try X.sign(&kp.sk, &sig, message); // advances kp.sk.idx — PERSIST sk first!

const ok = X.verify(kp.pk, message, &sig);
```

**STATEFUL-KEY HAZARD:** `sign` mutates `SecretKey.idx`. Persist the
updated key *before* releasing the signature; never sign from a restored
backup or from two copies of the key. If you cannot guarantee that, use
the stateless sibling module `slhdsa` instead. See SPEC.md.

`SigningKey` is an opt-in hardened handle for exactly these hazards: it runs the
whole exhaustion check → persist → sign → advance sequence under a lock (so
concurrent signers never repeat a leaf), refuses to sign from a copied or moved
handle (`error.KeyHandleCopied`), and calls your `Persist.write` hook with the
next index *before* any signature byte is produced (`error.PersistFailed` leaves
the leaf unconsumed). Initialise it in place with `SigningKey.init(&handle, &sk,
persist)`. A bare `SecretKey` is not thread-safe: two racing `sign` calls are a
memory-safety hazard, not only an index-reuse one.

**Not provided:** XMSS^MT (multi-tree), SHA-512/SHAKE suites, a serialisation of the secret key (see SPEC.md
*Backlog / deferred* and *What is deliberately not done*).

**Auth-path traversal is BDS (Buchmann–Dahmen–Schneider), not a naive
recompute:** `sign` emits the current leaf's auth path from `SecretKey.bds`
and advances it in ~O(h) hashing per signature (about verify cost), instead
of rebuilding the whole path in O(2^h) — cheap even at h = 20. An
out-of-band `idx` jump (index partitioning, a restored key) auto-resyncs
the BDS state in O(target·h) leaf generations before that one signature (hours
at h = 20), then stays O(h) again.
See SPEC.md for how this is validated (differential against a from-scratch
reference at every leaf for two heights, plus a dedicated resync test).

- **Model after:** RFC 8391 (public IRTF spec, clean-room); the XMSS
  reference implementation used only as a black-box KAT oracle (NOTICE).
  Fills a real std gap: Zig 0.17 `std.crypto` has no stateful hash-based
  signature (RFC 8391 XMSS / RFC 8554 LMS — the NIST SP 800-208 pair).
- **Deps:** none (std only — `std.crypto.hash.sha2.Sha256`).
- **Intended use:** firmware signing (IEC 62443-style code-signing
  chains standardize on SP 800-208 stateful HBS).

Provenance: clean-room from RFC 8391, a public IRTF specification, **with one
stated exception**: the BDS auth-path traversal is *ported* from the reference
`xmss_core_fast.c` (parameter k = 0), as `src/root.zig` and SPEC.md both say.
xmss-reference is **CC0** (public domain), so the port carries no licence
condition. Everything outside the BDS traversal is clean-room from the RFC, and
the reference was otherwise exercised only as a **black-box KAT oracle** — built,
run, and its output diffed against ours. Detail in this module's own
[`NOTICE`](NOTICE); it carries no condition beyond zig-libs' MIT license.
