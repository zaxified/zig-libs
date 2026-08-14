# xmss — spec

Design + threat notes for auditors. Usage: see ./README.md. Provenance:
clean-room from RFC 8391 (public IRTF spec); the official reference
implementation was used as a black-box test-vector oracle only — see
./NOTICE.

## Design & invariants

**Spec:** RFC 8391, "XMSS: eXtended Merkle Signature Scheme" (May 2018).
Implemented, single-tree XMSS over the SHA-256 suite (n = 32, w = 16,
len_1 = 64, len_2 = 3, len = 67):

- **§2.4/§2.5** toByte and the 32-byte ADRS hash-address structure
  (8 big-endian words: layer, tree(2), type, OTS/L-tree address, chain
  address/tree height, hash address/tree index, keyAndMask), with the
  "setType zeroes all following words" rule.
- **§5.1** keyed hash functions, SHA-256 suite: `F/H/H_msg/PRF =
  SHA-256(toByte(i, 32) || KEY || M)` for i = 0/1/2/3.
- **§3.1** WOTS+: Algorithm 1 (base_w), 2 (chain), 4 (genPK),
  5 (sign, incl. the checksum construction), 6 (pkFromSig).
- **§4.1** XMSS: Algorithm 7 (RAND_HASH), 8 (ltree), 9 (treeHash, fixed
  h+1-slot stack, no allocation), 10 (keyGen), 11/12 (treeSig/sign with
  the §4.1.9 randomized message hash `r = PRF(SK_PRF, toByte(idx, 32))`,
  `M' = H_msg(r || root || toByte(idx, n), M)`), 13/14
  (rootFromSig/verify).
- **Wire formats** (§4.1.7, §4.1.8, §B.3): public key
  `OID(4) || root(32) || SEED(32)`; signature
  `idx(4) || r(32) || sig_ots(67*32) || auth(h*32)`.
- **WOTS+ key derivation** (§3.1.7 / §4.1.11 leave this
  implementation-defined; interop-neutral): the NIST SP 800-208 /
  xmss-reference scheme — chain i start value =
  `SHA-256(toByte(4, 32) || SK_SEED || SEED || ADRS)` with ADRS = the OTS
  address with chainAddress = i, hashAddress = 0, keyAndMask = 0. The
  private key is therefore 4 seeds + a 4-byte index; one-time keys are
  derived on demand and never stored.

**Not implemented:** XMSS^MT (§4.2 multi-tree — different OID space and
hypertree signing); the SHA-512 and SHAKE suites (§5 OPTIONAL; RFC only
REQUIRES the SHA2-256 sets).

**Auth-path traversal — BDS, implemented (not the naive recompute).** RFC
8391 explicitly leaves auth-path computation implementation-defined
([BDS09] is cited but not mandated). This module ports the
Buchmann–Dahmen–Schneider log-space traversal from the reference
`xmss_core_fast.c` (parameter k = 0), held in `SecretKey.bds`: `sign`
emits the current leaf's precomputed auth path and advances the state to
the next leaf in ~O(h) hashing (about verify cost) instead of rebuilding
the whole path in O(2^h). The BDS state tracks `covered_idx` in lockstep
with `sk.idx`; a caller that jumps `idx` out of band (index partitioning,
a restored key) triggers an automatic O(2^h) resync so the emitted
signature is still byte-exact. `keyGen` remains O(2^h) (it now also seeds
the initial BDS state) — only per-signature auth-path cost is reduced.

## Statefulness — the key hazard

XMSS trades statelessness for small, fast signatures. The private key
contains `idx`, the next unused WOTS+ leaf. **Signing the same index
twice reveals two WOTS+ chain positions and enables forgery** — the
scheme's security argument collapses per-index, not per-signature.

- `sign` advances `sk.idx` **before** producing the signature (§4.1.9:
  "An implementation MUST NOT output the signature before the private
  key is updated") and returns `error.KeyExhausted` after 2^h uses.
- What the module CANNOT do for you (§4.1.12): persist the updated
  `SecretKey` durably before releasing each signature; never operate on
  a restored/older copy; partition index ranges if a key must be shared
  across signers.

## Validation — what is byte-exact vs round-trip

Oracle: the official XMSS reference implementation
(github.com/XMSS/xmss-reference @ HEAD 2026-07, built unmodified against
OpenSSL's SHA-256), driven with fixed deterministic inputs — generator
conventions documented in `src/kat_vectors.zig`.

Byte-exact against the oracle (committed test suite):

1. **Primitives:** PRF, the F chain step (thash_f), RAND_HASH (thash_h),
   H_msg — each on independent fixed inputs.
2. **WOTS+:** full pkGen (67×32 B), full sign (67×32 B), and
   pkFromSig(sig) == pk round-trip, on the reference's own test inputs.
3. **XMSS keygen + sign at h = 4** (reduced height, same suite/code
   path, test-only OID): public key and two complete wire signatures
   (leaf 0 and leaf 11) match the reference bit-for-bit.
4. **XMSS-SHA2_10_256 verify interop:** two reference-generated 2 500-B
   signatures (leaf 0 and leaf 517) verify under the reference's h = 10
   public key — a real external (pk, msg, sig) triple; 10 tamper/negative
   variants (bit flips in idx/r/WOTS/auth/message, grafted index,
   out-of-range index, truncation, wrong root) all reject.

Verified out-of-band (not in the committed suite — a Debug-mode h = 10
keygen costs ~40 s): `XmssSha2_10_256.keyGen` on the reference seed
reproduces the reference public-key root byte-exactly. h = 16/20 are the
same comptime code path, exercised only at h ≤ 10.

5. **h = 2 sequential stateful walk, byte-exact against the oracle for
   leaves 0-2:** the same fixed keypair seed as the h = 4/h = 10 vectors,
   signed leaf-by-leaf (idx 0, then 1, then 2 — a plain in-order advance,
   which nothing above exercises: the h = 4 vectors cover idx = 0 and an
   out-of-band jump to idx = 11, never idx -> idx+1 -> idx+2). Leaf 3
   (idx = 2^h - 1, the last one-time key) is deliberately NOT byte-anchored:
   capturing it exposed a bug in the reference implementation itself —
   `xmssmt_core_sign` wipes the secret key's index field to all-0xFF
   *before* copying it into the outgoing signature when
   `idx >= 2^h - 1`, so the reference's own emitted signature for the
   final leaf carries a corrupted index word and the reference's own
   `xmss_core_sign_open` rejects it (confirmed empirically while capturing
   these vectors: leaves 0-2 round-trip through the reference's own
   verifier, leaf 3 does not). This module's `sign` has no such bug — it
   writes the correct idx at every leaf, including the last, which the
   h = 4/h = 6 exhaustive BDS sweeps already check byte-for-byte against
   an independent from-scratch auth-path build — so leaf 3 stays a
   behavioral check (signs, verifies, then `KeyExhausted` on the 5th
   attempt) rather than an external byte anchor. See kat_vectors.zig for
   the full provenance note.

**BDS traversal, differential against a from-scratch reference (no
external oracle for this — RFC 8391 leaves it implementation-defined, so
there is no third-party BDS vector to match; the reference oracle instead
is this module's own naive `buildAuth`, a full O(2^h) recompute):** the
h = 4 exhaustive sweep signs and verifies every one of the 16 leaves,
byte-comparing the BDS-produced auth path against `buildAuth` at each
index; the h = 6 sweep does the same for all 64 leaves, with the
differential re-run at the boundary indices around the 2^(h-1)
left/right-subtree transition (the part of BDS most likely to be
mis-ported); a dedicated test jumps `idx` out of band (skipping several
leaves, and landing exactly on the h = 6 transition leaf) and confirms
the auto-resync still reproduces the from-scratch auth path byte-exactly.

## Threat notes

- **verify** is public-data-only: plain `std.mem.eql` root comparison is
  correct (nothing secret to leak); malformed lengths and out-of-range
  indexes are rejected before any hashing.
- **sign/keyGen** are not constant-time hardened. Hash-based schemes have
  no secret-dependent branching in the algorithm itself beyond hashing
  secret chain values; still, treat timing as out of scope.
- **No internal RNG:** keyGen takes caller-supplied `sk_seed`, `sk_prf`
  (secret) and `pub_seed` (public but MUST be high-entropy, §4.1.3) —
  bring a CSPRNG (std 0.16 removed `std.crypto.random`). Everything is
  deterministic, which is what makes the KATs byte-exact.
- **No allocation, no I/O:** all buffers are fixed-size (largest:
  the 67×32 B WOTS+ arrays and the h+1-slot treeHash stack).
- **OID discipline:** `PublicKey.fromBytes` rejects foreign OIDs; the
  reduced-height test instantiations use private-range OIDs
  (0xDDDDDDDD–0xFFFFFFFF are never IANA-assigned).

## Anchoring

**Anchor grade:** class B · oracle MIXED

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** core hashes/WOTS+/sig vs real XMSS reference(EXTERNAL); h=2 stateful walk is round-trip only

**How it got there.** The anchoring work landed. DONE 5938bfc: h=2 anchored on XMSS/xmss-reference; leaf 3 = BUG IN THE REFERENCE
