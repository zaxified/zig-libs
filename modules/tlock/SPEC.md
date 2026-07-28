# tlock — SPEC

drand-style timelock encryption (Boneh-Franklin IBE over
`bls12_381`) — see [README.md](README.md) for purpose and API.
Provenance: see [NOTICE](NOTICE).

**Status: REAL — interop-verified.** `ciphersuite.zig` (hashes/DSTs),
`tlock.Ciphertext` (wire struct + codec), and `tlock.encrypt`/
`tlock.decrypt` (the BF-IBE FullIdent core, implemented 2026-07-16)
are all real and tested; `gate.core_implemented = true`. Both cores
are byte-exact-verified against a GENUINE ciphertext produced by
drand's own Go implementation (see "KAT plan" below — the interop
vector caught and fixed a real Gt-representation divergence).

## Scheme variant pinned: quicknet / `SigsOnG1ID`

drand runs four schemes; two are usable for timelock encryption at all
(the chained default scheme folds the previous signature into its
digest, so its "identity" for a future round is unknowable ahead of
time — `drand/tlock`'s own `TimeLock`/`TimeUnlock` `switch` excludes
it). Of the two usable ones this module targets **quicknet**'s
`SigsOnG1ID` (`"bls-unchained-g1-rfc9380"`) — confirmed live
(2026-07-16) against `https://api.drand.sh/v2/beacons/quicknet/info`
returning exactly that scheme name — NOT the older, deprecated
`ShortSigSchemeID` (`"bls-unchained-on-g1"`, which reuses the `G2` DST
for `G1` hashing, a known RFC-9380 non-conformance kept only for
retro-compatibility).

**The naming trap**: `SigsOnG1ID`'s own name suggests "everything on
G1", but `drand/tlock`'s `tlock.go` routes it through
`ibe.EncryptCCAonG2`/`DecryptCCAonG2` — master public key `P_pub` AND
the ciphertext's `U` point both live in `G2` (96-byte compressed); only
the per-round beacon signature (the BF-IBE private key) lives in `G1`
(48-byte compressed). See `ciphersuite.zig`'s module doc comment
("Variant confirmation") for the byte-level evidence trail
(`schemes.go`'s `KeyGroup = Pairing.G2()`, `SigGroup = Pairing.G1()`
for this scheme).

## The construction (Boneh-Franklin "FullIdent", CRYPTO 2001 §4.2)

```
Setup (external, caller-supplied):
  P_pub ∈ G2                              — beacon master public key
  σ_round ∈ G1, e(σ_round,G2gen)==e(H1(id),P_pub) — round signature == IBE private key

id = beaconId(round) = SHA-256(BigEndian64(round))     — REAL (ciphersuite.zig)
Qid = H1(id) = hashToCurveG1(id, dst_g1)                — REAL

encrypt(P_pub, round, M, sigma):        [FABLE CORE — tlock.encrypt]
  Gid   = pairing(Qid, P_pub) ∈ Gt
  r     = H3(sigma, M) ∈ Fr
  U     = r · G2_generator ∈ G2
  gid_r = Gid^r ∈ Gt                    (Gt SCALAR EXPONENTIATION — see "Known gap" below)
  V     = sigma XOR H2(gid_r)
  W     = M XOR H4(sigma)
  return (U, V, W)

decrypt(σ_round, (U,V,W)):              [FABLE CORE — tlock.decrypt]
  gid_r = pairing(σ_round, U) ∈ Gt      (ONE pairing call — bilinearity gives gid_r for free)
  sigma = V XOR H2(gid_r)
  M     = W XOR H4(sigma)
  r'    = H3(sigma, M)
  if r'·G2_generator != U: REJECT (error.FoCheckFailed)   — Fiat-Shamir-Okamoto CCA check
  return M
```

`H2`/`H3`/`H4` are drand/kyber's own SHA-256-based constructions
(`ciphersuite.h2`/`h3`/`h4` — see that file's doc comments for the
exact byte layout, including the one little-endian counter inside
`H3`'s rejection-sampling loop, everything else being big-endian).

## `Gt` (`Fp12`) scalar exponentiation — RESOLVED (option 1 taken)

`encrypt` needs `Gid^r`; `bls12_381.Fp12` exports no `pow`. **Decision
(2026-07-16 Fable pass): option 1** — a module-local `fp12Pow` in
`tlock.zig`: a constant-time square-and-multiply-ALWAYS loop over
`Fp12.square`/`.mul` and a component-wise `Fp2.ctSelect` lift (the
same branchless idiom `g1`/`g2.scalarMulBytes` use; `r = H3(sigma, M)`
is secret-derived, so the exponent is treated like a secret scalar).
No `bls12_381` change — mirrors how `vdf`'s `pow2Mod` is module-local.
Its exponentiation law is pinned ungated against pairing bilinearity
(`e(P,Q)^r == e(rP,Q)`) in `tlock.zig`'s tests. Option 2 (an upstream
`Fp12.pow`) remains open as a future `bls12_381` refactor if a second
consumer appears.

## `Gt` serialization — RESOLVED (byte-exact-verified, one real divergence found)

The scaffold flagged this as the critical unverified footgun. The
interop vector proved the flag right, in an unexpected place:

- **Byte nesting: identical, as predicted.** kilic/bls12-381's
  `GT.ToBytes` layout (`c1||c0` per tower level, `c2||c1||c0` inside
  `Fp6`, big-endian 48-byte `Fp` limbs) is exactly
  `bls12_381.Fp12.toBytes` — NO reordering needed.
- **Pairing VALUE: kilic's is the canonical value's CUBE.** kilic's
  final exponentiation uses the Fuentes-Castañeda-Knapp-Rodríguez-
  Henríquez (ePrint 2011/465) hard-part chain, which computes
  `f^(3d)`; this repo's `bls12_381.pairing` deliberately implements
  the exact-`d` Hayashida et al. (ePrint 2020/875) chain, pinned
  against the IETF pairing-friendly-curves draft's canonical KAT
  (see `pairing.zig`'s `finalExpHardPart` doc comment). Both are
  bilinear and non-degenerate (`gcd(3, r) = 1`), so EVERY
  self-consistent test passes under either convention — only a
  cross-implementation byte vector can tell them apart. Verified
  empirically two independent ways: (a) kilic's own published pairing
  output vectors (noble-curves' `go_pairing_vectors/pairing.json`,
  generated directly by `kilic/bls12-381`; vector `n` equals
  `canonical^(3n²)` byte-for-byte in `Fp12.toBytes` layout, checked
  against `ethereum/py_ecc` ground truth for multiple `n`), and
  (b) the real drand decrypt vector below, which rejects without the
  cube and decrypts byte-exactly with it.
- **Fix:** `tlock.zig`'s private `gtToDrandRepr` (`gt -> gt³`) applied
  to the pairing/`fp12Pow` output before every `ciphersuite.h2` call
  (`(gid^r)³ = (gid³)^r`, so cubing after exponentiation equals
  drand's exponentiating its own cubed `Gid`). `ciphersuite.h2`'s
  definition itself is untouched — the caller supplies the element in
  drand's representation.

## KAT plan

- **Hashes/`H1` (REAL, ungated, done)**: `beaconId` byte-exact against
  an independently (Python) computed SHA-256 digest;
  `h1(beaconId(round))` checked on-curve + in-subgroup; and — the
  strongest check achievable WITHOUT the IBE core —
  `kat_test.zig`'s pairing-sanity test verifies
  `e(σ_1000, G2gen) == e(h1(beaconId(1000)), P_pub)` against GENUINE,
  live-fetched quicknet production data (chain hash
  `52db9ba7...c84e971`, round 1000 — see `NOTICE`). This is a REAL
  interop check: `beaconId`'s digest construction and `h1`'s DST are
  BOTH confirmed correct against an actual published beacon round,
  using only `bls12_381`'s already-real `hash_to_curve`/`pairing`.
- **`Ciphertext` codec (REAL, ungated, done)**: round-trip +
  malformed-`G2`-rejection.
- **drand interop, byte-exact (GATED, done — the primary vector)**:
  a GENUINE Go-`tle`-produced ciphertext, decrypted byte-exactly.
  Source: `github.com/drand/tlock` commit `7ceb44a598293f10c43d2291df
  9e669c4251fe24`, `testdata/lorem-tle-testnet-quicknet-t-2024-01-17-
  15-28.tle` — encrypted to testnet beacon quicknet-t (chain
  `cc9c3984...41a9a5`, scheme `"bls-unchained-g1-rfc9380"`, IDENTICAL
  to mainnet quicknet's), round 5423142. The age file's `tlock` stanza
  body is the raw 128-byte `(U,V,W)`; the round signature was fetched
  live from `https://pl-us.testnet.drand.sh` (2026-07-16) and is
  pinned by an ungated pairing-sanity test against the quicknet-t
  public key. The expected plaintext (the 16-byte age file key)
  recovered by `decrypt` was INDEPENDENTLY verified outside Zig: it
  authenticates the fixture's age header (HKDF-SHA256/HMAC-SHA256,
  byte-exact MAC) and its ChaCha20-Poly1305 payload decrypts to a
  byte-identical copy of the same commit's `testdata/lorem.txt`.
  `encrypt` is interop-pinned by the same vector: re-encrypting the
  recovered `(filekey, sigma)` reproduces the Go ciphertext's 128
  bytes exactly. Gated tests in `kat_test.zig` section 3
  (decrypt byte-exact, re-encrypt byte-exact, cross-beacon FO
  rejection).
- **Round-trip against a real quicknet round signature (GATED,
  done)**: `encrypt` a fixed `(message, sigma)` under the REAL
  mainnet quicknet `P_pub`, `decrypt` with the REAL round-1000
  signature — `kat_test.zig`'s "round trip" test, now running.
- **`encrypt` determinism with fixed `sigma` (GATED, done)**.
- **Soundness/CCA (GATED, done)**: tampered `V`/`W`, a wrong-round
  signature, and a cross-beacon signature all return
  `error.FoCheckFailed`, never a garbage plaintext (four tests).
- **`fp12Pow` law (ungated, done)**: `base^0/base^1`, exponent
  additivity, and the bilinearity cross-check `e(P,Q)^r == e(rP,Q)`.

## Out of scope

- The hybrid `age`-envelope layer (`filippo.io/age` stanzas, armored
  file framing, arbitrary-length payloads) `drand/tlock`'s `tle` CLI
  wraps this primitive inside of. This module implements the raw
  128-byte BF-IBE `Ciphertext` only.
- PQ-hybrid composition (see `root.zig`'s "Honest limitations" —
  gating a `hqc` KEM ciphertext alongside this module's IBE layer for
  long-term confidentiality) — a consumer-side decision, not this
  module's job.
- Threshold/DKG beacon operation itself — `p_pub`/`round_signature` are
  always caller-supplied; this module never runs a drand node.
- The BN254 variant (`BN254UnchainedOnG1SchemeID`) `tlock.go` also
  supports — a different curve family entirely (this repo's `bn254`
  module, not `bls12_381`); a separate module extension, not in scope
  here.
