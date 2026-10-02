# tsslib — key-material interop oracle for `threshold_ecdsa`

A Go program around [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) v3.0.0
(MIT). The Zig module and tss-lib use different Fiat-Shamir transcripts, so proofs
cannot be compared byte for byte. The outside anchor is **key-material interop**
in both directions:

* **A** — tss-lib's own dealer-free keygen output (n=3, 2 signers needed) is exported
  in an interchange format; the Zig signer must be able to sign with it.
* **B** — key material produced by the Zig module (trusted-dealer Shamir) is imported
  into tss-lib, which must sign with it; the signatures must verify with Go's
  `crypto/ecdsa`.

Message: ASCII `zig-libs threshold_ecdsa / tss-lib interop v1`. Both sides sign
SHA-256(message) (tss-lib gets the digest as its `msg` big.Int, `fullBytesLen=32`).
Signatures are low-S.

## Subcommands

* `keygen -keys K.json -sigs S.json` — runs tss-lib keygen in-process (3 parties,
  `PartyID.Key` = 1, 2, 3, tss-lib threshold 1), with freshly generated pre-params
  (slow: 12 safe primes of 1024 bits, minutes; full mod/fac proofs on). Writes K.json,
  then signs with every 2-subset, checks each with `ecdsa.Verify`, writes S.json.
  Exits non-zero on any failure.
* `sign -keys K.json -sigs S.json` — reads interchange key material (e.g. from the Zig
  module), builds tss-lib `LocalPartySaveData` for every party, signs with every
  2-subset, verifies each with `ecdsa.Verify` against `public_key`. Before signing the
  importer checks: `x*G == big_x`, `aux_p_safe*aux_q_safe == n_tilde`,
  `h1^aux_lambda == h2`, and that the first t `big_x` interpolate to `public_key`.
* `zigvectors -tsslib-keys a -tsslib-sigs b -zig-keys c -zig-sigs d` — prints a Zig
  source file (`tsslib_keygen`, `zig_keys_tsslib_signed` constants) to stdout.

## Commands (from `modules/threshold_ecdsa`)

```sh
T=tools/tsslib
# direction A (once; committed result: tsslib_keys.json / tsslib_sigs.json)
hw run --name tsslib --slots 1 --timeout 1800 -- bash -c \
  "cd $T && go run . keygen -keys tsslib_keys.json -sigs tsslib_sigs.json"
# direction B: this module's key material (12 safe primes of 1024 bits, ~4 min)...
hw run --name tsslib --slots 1 --timeout 3000 -- bash -c \
  "zig run -OReleaseFast -fllvm --cache-dir ../../.zig-cache \
     --dep threshold_ecdsa --dep paillier -Mroot=$T/emit_zig_keys.zig \
     --dep paillier --dep montint -Mthreshold_ecdsa=src/root.zig \
     --dep montint -Mpaillier=../paillier/src/root.zig -Mmontint=../montint/src/root.zig \
     > $T/zig_keys.json"
# ...signed by tss-lib (exits non-zero unless ecdsa.Verify accepts every signature)
hw run --name tsslib --slots 1 --timeout 1800 -- bash -c \
  "cd $T && go run . sign -keys zig_keys.json -sigs zig_tsslib_sigs.json"
# Zig vectors
hw run --name tsslib --slots 1 --timeout 600 -- bash -c \
  "cd $T && go run . zigvectors -tsslib-keys tsslib_keys.json -tsslib-sigs tsslib_sigs.json \
     -zig-keys zig_keys.json -zig-sigs zig_tsslib_sigs.json > ../../src/tsslib_vectors.zig"
```

Committed: `tsslib_keys.json`/`tsslib_sigs.json` (direction A, 2026-10-02),
`zig_keys.json`/`zig_tsslib_sigs.json` (direction B, 2026-10-02 — tss-lib accepted
this module's material on the first run), and the generated
`src/tsslib_vectors.zig` that `src/tsslib_interop.zig` tests against. The key
files hold SECRET shares and Paillier/aux factors of throwaway test keys,
on purpose: the Zig test rebuilds `KeyShare`s from them.

## Interchange format

JSON, all byte strings lowercase hex, big-endian, no `0x`. `t` = signers needed
(tss-lib threshold = t-1). Per party: `index` (Shamir x-coordinate = `PartyID.Key`),
`x` (32-byte share), `big_x` (33-byte compressed x*G), `paillier_p/q` (N = p*q,
g = N+1), `n_tilde`, `h1`, `h2`, `aux_p_safe`, `aux_q_safe` (n_tilde = p~*q~,
safe primes p~ = 2p'+1), `aux_lambda` (h2 = h1^lambda mod n_tilde). Top level:
`public_key` (33-byte SEC1 compressed). Signatures file:
`{"message": ..., "signatures": [{"signers": [1,2], "r": ..., "s": ...}]}`.

## Field mapping (tss-lib `LocalPartySaveData`)

| tss-lib | interchange |
|---|---|
| `ShareID`, `Ks[j]` | `index` (1..n); `Ks` sorted ascending |
| `Xi` | `x` |
| `BigXj[j]` | `big_x` |
| `ECDSAPub` | `public_key` |
| `PaillierSK.P`, `.Q` | `paillier_p`, `paillier_q` (tss-lib generates safe primes here; signing does not need that) |
| `PaillierSK.N`, `PaillierPKs[j]` | `paillier_p * paillier_q` |
| `PaillierSK.LambdaN` / `PhiN` | derived: lcm / product of (p-1), (q-1) |
| `NTildei`, `NTildej[j]` | `n_tilde` |
| `H1i`, `H1j[j]` | `h1` |
| `H2i`, `H2j[j]` | `h2` |
| `LocalPreParams.P`, `.Q` | **Sophie Germain primes** p', q': `(aux_p_safe-1)/2`, `(aux_q_safe-1)/2` (NTilde = (2P+1)(2Q+1)) |
| `LocalPreParams.Alpha` | `aux_lambda` (h2 = h1^Alpha mod NTilde) |
| `LocalPreParams.Beta` | derived: Alpha^-1 mod P*Q (P, Q Sophie Germain) |

Paillier generator is `N+1` (tss-lib `Gamma()`), matching the interchange format.

## tss-lib validation our material must satisfy

* Signing itself performs no `ValidateWithProof`; that is checked only when
  pre-params are handed to *keygen* / *resharing* (`LocalPreParams.ValidateWithProof`:
  all of PaillierSK incl. P, Q, NTildei, H1i, H2i, Alpha, Beta, P, Q non-nil).
  The importer fills all of them anyway.
* Signing rounds do use: Paillier decrypt (needs `LambdaN`, `PhiN`), range/MtA
  proofs against `NTildej/H1j/H2j` of the *verifying* peer (h1, h2 must generate the
  same subgroup, i.e. h2 = h1^lambda), `PrepareForSigning` (Lagrange over `Ks` and
  `BigXj`, so `big_x` must be consistent with `x` and with `public_key`).
* The message integer must be < group order q.
* Wire proofs (mod/fac/dln) are never involved in signing of imported keys, so the
  Zig module's proofs are not exercised by `sign`; only the key material is.
