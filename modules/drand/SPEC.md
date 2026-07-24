# drand — SPEC

Auditor/design reference for the `drand` module. Purpose + API live in
[README.md](README.md); this file records how/why it is built, the
verification algorithm, the threat model, and what is deliberately
deferred.

## What it is

A drand randomness-beacon **client core**: the verification + codec
layer. It parses the two JSON documents a drand HTTP node serves
(`/info` and `/public/<round>`) into typed, plain-value structs, and
BLS-verifies a round's threshold signature against the chain public key.
It performs no I/O — the caller fetches the bytes over their own HTTPS
transport (see "Transport boundary").

## Schemes and the exact message hashing

drand runs several schemes; the signed message per round differs by
scheme. This module VERIFIES only quicknet and RECOGNIZES the others.

### quicknet — `bls-unchained-g1-rfc9380` (verified)

- Signatures live in **G1** (48-byte compressed), the master public key
  in **G2** (96-byte compressed).
- The signed message is `beaconId(round) = SHA-256(I2OSP(round, 8))` —
  the round number ALONE, big-endian, no previous signature folded in
  (that is what "unchained" means).
- That 32-byte digest is hashed to the curve with RFC 9380 hash-to-curve
  onto G1 under the DST
  `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`:
  `Qid = H1(beaconId(round))`.
- Both `beaconId` and `H1` are REUSED verbatim from
  `tlock.ciphersuite` (`tlock` targets the identical scheme), so the two
  modules can never disagree on quicknet.

### chained — `pedersen-bls-chained` (recognized, not verified)

- Signatures in **G2**, key in **G1**; the message folds in the previous
  signature (`H(round ‖ prev_sig)`). `parseInfo`/`parseRound` retain what
  they can (metadata, raw key bytes, `previous_signature`) but leave the
  decoded point `null`; `verifyRound` returns `error.UnsupportedScheme`.

### `bls-unchained-on-g1` (recognized, not verified)

- The deprecated pre-RFC-9380 unchained scheme, which reuses the G2 DST
  for G1 hashing (a known non-conformance). Recognized, not verified.

## The verification algorithm

quicknet's verify is drand's `crypto.Scheme.VerifyBeacon`, i.e. the BLS
verification equation with signatures and key in the SWAPPED groups
relative to `bls12_381.bls_sig`:

```
e(signature, G2_generator) == e(H1(beaconId(round)), public_key)
```

evaluated as a single multi-pairing identity check
(`bls12_381.pairing.pairingCheck`) with the second pairing's G1 point
negated, so the product is the target-group identity iff the equation
holds. No cryptography is reimplemented in this module: the pairing and
hash-to-curve are `bls12_381`'s, and the message hashing is
`tlock.ciphersuite`'s.

### Why not `bls12_381.bls_sig.verify`

`bls_sig` implements the **minimal-pubkey-size / ProofOfPossession**
ciphersuite: keys in G1, signatures in G2, messages hashed to G2 under
`..._RO_POP_`. quicknet is the mirror image (sig in G1, key in G2, hash
to G1 under `..._RO_NUL_`). Both the groups AND the DST differ, so
`bls_sig.verify` structurally cannot verify a quicknet round — hence the
direct pairing check. (This corrected a premise in the build brief,
which assumed `bls_sig.verify` plus a DST swap would suffice.)

### randomness

drand defines `randomness = SHA-256(signature)`. When the round document
carried a `randomness` field, `verifyRound` also asserts that identity
(`error.RandomnessMismatch` otherwise), protecting a caller who consumes
`randomness` downstream from a document whose randomness was tampered
independently of the signature.

## JSON shapes parsed

`/info` (fields consumed): `public_key` (hex), `period` (u64 seconds),
`genesis_time` (u64 unix seconds), `hash` (32-byte hex), `groupHash`
(32-byte hex), `schemeID` (string), `metadata.beaconID` (string).
Unknown fields are ignored (forward-compatible).

`/public/<round>` (fields consumed): `round` (u64), `signature` (hex),
`randomness` (32-byte hex, optional), `previous_signature` (hex,
optional — chained schemes).

## Transport boundary

The module never opens a socket or terminates TLS — consistent with
`CONVENTIONS.md` §2 (bring-your-own transport) and mirroring `tlock`,
which consumes a round signature without fetching it. The caller runs an
HTTPS client, GETs `<host>/<chainhash>/info` and
`<host>/<chainhash>/public/<round>` (or the `/v2/beacons/<id>/...`
forms), and passes the raw response bodies to `parseInfo`/`parseRound`.
`roundPath`/`latestPath` build the path string only.

## Malformed-input handling (threat model)

Every parser is pure and bounds-checked. The relevant adversary is a
malicious or corrupt beacon endpoint (or a MITM the caller's TLS did not
stop) feeding crafted bytes:

- **Oversized input** → rejected at `max_document_bytes` (64 KiB) before
  any parse, so a huge body cannot induce a large allocation. Allocation
  is otherwise bounded by input size (an internal arena freed before
  return); parsing does not amplify.
- **Malformed / truncated JSON, wrong types, missing field, trailing
  garbage** → `MalformedJson` (a coarse typed error), never a panic.
- **Bad / odd-length / wrong-length hex** → `InvalidHex` /
  `InvalidLength`.
- **Invalid or non-subgroup public key** → `InvalidPoint` /
  `PublicKeyNotInSubgroup`. drand `KeyValidate` (on-curve + order-`r`
  subgroup, non-identity) runs on the quicknet key at parse time, because
  `bls12_381`'s `fromBytesCompressed` deliberately does NOT subgroup-
  check (that module's documented pitfall — callers at trust boundaries
  must, and this module is that boundary).
- **Wrong signature / wrong round / wrong chain key** → the pairing
  equation fails → `InvalidSignature`. Never a silent false-accept.
- **Number overflow** (`period`/`genesis_time` past `u64`) →
  `MalformedJson` (std.json's `error.Overflow`).

A `std.testing.fuzz` harness drives arbitrary bytes through both parsers
and the verify path, asserting no panic / OOB / hang.

## Verification bar / KAT

The genuine known-answer vector is **quicknet round 1000**: the master
public key (G2) and the round-1000 threshold signature (G1) are the same
live-fetched League-of-Entropy production bytes `tlock`'s KAT harness
pins (`modules/tlock/src/kat_test.zig`), which are in turn cross-checked
there by a pairing-sanity test. `randomness` for round 1000 is
`SHA-256(signature)` (drand's definition). `verifyRound` returns success
on the genuine round and rejects: a flipped signature byte, the correct
signature under the wrong round number, the signature against a
different chain's key (quicknet-t testnet), and tampered randomness.

**Positive control (permanent):** a test deliberately hashes the round
number little-endian and shows the genuine KAT then FAILS to verify —
proving the big-endian round encoding is load-bearing, not incidental.

## Provenance

Spec/RFC-and-public-data only — no third-party source ported, no
third-party implementation studied as a design reference beyond drand's
publicly documented wire format and verification equation (which are a
spec, not a copyrightable work — `CONVENTIONS.md` §5 merger doctrine).
The quicknet KAT bytes are the same genuine, publicly-served beacon data
`tlock` pins. No `NOTICE` entry is required; the message construction and
DSTs are documented in `tlock`'s `ciphersuite.zig` (which cites drand's
Go source) and reused here.

## Deliberately deferred

- **Chained-scheme verification** (`pedersen-bls-chained`): different
  groups (sig in G2, key in G1), a different message (`H(round ‖
  prev_sig)`), and the older non-RFC-9380 DST. Recognized + parsed, not
  verified; no genuine KAT vector on hand. Would need G2 hash-to-curve
  under the legacy DST.
- **`bls-unchained-on-g1`** (deprecated non-conformant DST): recognized,
  not verified.
- **HTTP / TLS transport, retries, endpoint discovery, gossip/libp2p**:
  out of scope by design (caller-supplied bytes).
- **Group file / DKG / distributed-key parsing** (`/group`): not parsed;
  only `/info` and `/public/<round>`.
- **Round ↔ wall-clock time arithmetic** (`round_at(time)` from
  `genesis_time`/`period`): the inputs are parsed and exposed, but the
  helper itself is not shipped yet.
