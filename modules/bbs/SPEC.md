# bbs — SPEC

BBS signatures — pairing-based multi-message signatures with
zero-knowledge selective-disclosure proofs; see [README.md](README.md)
for purpose and API. Provenance: see [NOTICE](NOTICE).

**Status: COMPLETE.** Ciphersuite machinery, key generation, the
`Signature`/`Proof` wire codecs, and the four irreducible cryptographic
cores — `sign`/`verify`/`proofGen`/`proofVerify` (`bbs.zig`) — are all
implemented and byte-exact KAT-pinned. `gate.core_implemented = true`;
the full suite passes byte-exact in Debug and ReleaseFast.
See `bbs.zig`'s own module doc comment for the exact construction each
core transcribes.

## Draft version pinned: draft-irtf-cfrg-bbs-signatures-**04**

The BBS Signatures IETF draft is NOT a stable target — its ProofGen
transcript and CoreSign construction both changed across revisions
while this module was being scaffolded. Rather than target the current
draft (`-10` as of this scaffold, fetched 2026-07-16 from
`https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.txt`),
this module pins **draft-04** (`https://www.ietf.org/archive/id/
draft-irtf-cfrg-bbs-signatures-04.txt`, dated October 2023), because
that is the exact version whose test vectors are what
`mattrglobal/pairing_crypto` (the reference implementation this
module's KAT vectors are drawn from — see below) currently ships.

**How the exact version was determined** (there is no single
"vectors are for draft N" label in that repository — this required
byte-level detective work, recorded here for auditability):

1. `mattrglobal/pairing_crypto`'s git history shows the fixtures
   directory was updated to "Draft version 06" (commit `b35fd0e`,
   2024-07-08), then that update was REVERTED (commit `b91a807d6a2d1
   d3bb039f2d67a53e21b686b7395`, 2025-09-05) — the state pinned here.
2. The reverted-to fixtures' `KeyPair`/generator constants (`P1`'s
   published literal, the `h2s` worked example) are IDENTICAL across
   every draft revision `-03` through `-10` — these do not
   discriminate a version.
3. `signature/signature001.json`'s exact signature bytes appear
   (verified via a collapsed-whitespace substring search) in drafts
   `-03`, `-04`, and `-05`'s own embedded Appendix vectors, but NOT in
   `-06` or later — CoreSign's construction changed at `-06`.
4. `proof/proof001.json`'s exact proof bytes appear in drafts `-03`
   and `-04` only, NOT `-05` or later — ProofGen's transcript changed
   at `-05` (and again at `-06`, per that repo's now-reverted commit
   message "move the challenge at the end of the proof").
5. The intersection of (3) and (4) is **draft-04** — confirmed
   additionally by that draft's own page header reading "October
   2023" (matching its actual IETF submission date, 2023-10-23, fetched
   from `https://datatracker.ietf.org/api/v1/submit/submission/135422/`).

**Fixture source**: `mattrglobal/pairing_crypto`, commit
`b91a807d6a2d1d3bb039f2d67a53e21b686b7395`, path
`tests/fixtures/bbs/bls12_381_sha_256/` — `keypair.json`,
`generators.json`, `h2s.json`, `MapMessageToScalarAsHash.json`,
`mockedRng.json`, `signature/signature{001,002,004}.json`,
`proof/proof{001,003,004}.json`. Transcribed verbatim into
`src/kat_vectors.zig`.

**Mocked-RNG seed provenance** (not published in the draft text
itself — confirmed from the fixture GENERATOR's source, not merely
inferred from the fixture JSON): `mattrglobal/pairing_crypto`'s
`tools/bbs-fixtures-generator/src/mock_rng.rs` hardcodes
`MOCKED_RNG_SEED = "3.141592653589793238462643383279"` (the first 30
digits of pi) and `MOCKED_RNG_DST = "MOCK_RANDOM_SCALARS_DST_"` as
GLOBAL constants reused — with a per-fixture `count = messages.len -
disclosed_indexes.len + 3` — across every `proof*.json` fixture in that
directory (`tools/bbs-fixtures-generator/src/generators/proof.rs`'s
`proof_gen_helper!` macro). This is what makes `kat_test.zig`'s gated
`proofGen` tests possible at all: without confirming this SAME seed is
shared across fixtures (rather than each fixture using its own,
unpublished seed), there would be no way to reproduce `proof001.json`/
`proof003.json`'s exact bytes from the published fixtures alone.

## Why `proofGen`/`proofVerify`, not `sign`/`verify`, are the Fable-hard core

See `bbs.zig`'s module doc comment — restated briefly: `sign`/`verify`
are a direct, unambiguous transcription of a single Schnorr-like
pairing signature (draft §3.6.1/§3.6.2), with no per-call design
choice. `proofGen`/`proofVerify` are a full Fiat-Shamir NIZK: the
blinding-factor roles (`r1`/`r2`/`r3`/`m~_j`), the `Abar`/`Bbar`/`T`
accumulation order, which generators get disclosed-vs-undisclosed
treatment in `ProofVerifyInit`'s `D`/`T` split, and the exact
transcript `ProofChallengeCalculate` folds into the challenge `c` are
all genuine soundness-critical judgment calls — get any one backwards
and the result can still compile, run, and even pass a lazy
prove-then-verify smoke test while being completely unsound.

## Ciphersuite: BLS12-381-SHA-256

`BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_` — public keys in `G2`
(`bls12_381.G2`, 96-byte compressed), signatures/generators/proof
points in `G1` (`bls12_381.G1`, 48-byte compressed), `Fr` scalars
32-byte big-endian. The SHAKE-256 variant
(`BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_`) exists in the draft but is
explicitly OUT OF SCOPE here (per the task brief: "do SHA-256 first") —
adding it later is a `ciphersuite.zig`-local extension (a second
ciphersuite-constants file reusing the same `bls12_381` primitives
with `expand_message_xof`/SHAKE-256 in place of `expand_message_xmd`/
SHA-256 — `bls12_381.hash_to_curve` does not currently expose an XOF
variant either, so that would be a joint `bls12_381` + `bbs` extension,
not a `bbs`-local one).

## Randomness — explicit parameter, not internal entropy

See `root.zig`'s "Randomness" section (the normative statement of this
design choice) — `bbs.proofGen` takes `random_scalars: []const Fr` as
a plain parameter rather than reading `std.Io`/internal entropy, so the
deterministic mocked-RNG KAT vectors and real production entropy share
one code path via two different scalar SOURCES
(`ciphersuite.mockedRandomScalars`/`calculateRandomScalars`). This
follows `frost`'s "nonces are an explicit input" convention
(`frost/src/root.zig`).

## Deserialization does not subgroup-check

Same pitfall class `bls12_381`'s own `SPEC.md` centers its threat
model on: `G1.fromBytesCompressed`/`G2.fromBytesCompressed` (and
therefore `Signature.fromBytes`/`Proof.fromBytes`/
`PublicKey.fromBytes`, all built on them) validate on-curve-ness and
reject the identity where the draft requires it, but do NOT check
subgroup membership. A future Fable pass implementing `sign`/`verify`/
`proofGen`/`proofVerify` MUST decide — and document — where a
mandatory `subgroupCheck` belongs on each entry point's untrusted
input (`PK`, a deserialized `Signature`/`Proof`), mirroring
`bls12_381.bls_sig.keyValidate`'s explicit, reusable check.

## Cores (implemented) — draft mapping

- `bbs.sign` — CoreSign (draft §3.5.1/§3.6.1). Byte-exact vs
  `signature001`/`signature004`.
- `bbs.verify` — CoreVerify (draft §3.5.2/§3.6.2). Tamper-rejects
  `signature002`.
- `bbs.proofGen` — ProofGen/CoreProofGen/ProofInit/ProofFinalize/
  ProofChallengeCalculate (draft §3.5.3/§3.6.3/§3.7.1/§3.7.2/§3.7.4).
  **The genuinely hard core.** Byte-exact (under the draft's
  deterministic mocked RNG) vs `proof001`/`proof003`.
- `bbs.proofVerify` — ProofVerify/CoreProofVerify/ProofVerifyInit/
  ProofChallengeCalculate (draft §3.5.4/§3.6.4/§3.7.3/§3.7.4).
  Tamper-rejects `proof004` (altered presentation header).

`gate.core_implemented = true`; `kat_test.zig`'s gated tests are all
executed assertions (byte-exact against `signature001`/`signature004`/
`proof001`/`proof003`, tamper-rejection against `signature002`/
`proof004`).

## Remaining hardening

- The subgroup-check obligation noted above on each of the four
  functions' untrusted inputs (`PK`, deserialized `Signature`/`Proof`)
  is deferred — deserialization validates on-curve-ness and rejects the
  identity where the draft requires, but does not yet subgroup-check.

## Out of scope (future extensions)

- The SHAKE-256 ciphersuite variant (see above).
- The blind-signature `commitment` extension point (draft §5.11) —
  `CoreSign`'s `commitment` parameter always defaults to `Identity_G1`
  in this module's `sign`; a blind-BBS extension would need its own
  Interface layer per draft §3.8's "Defining New Interfaces" rules.
- A `bbs.Proof`-level "which messages are disclosed" convenience API
  beyond the raw `disclosed_indexes: []const usize` this scaffold
  exposes.

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** KAT vectors drawn from published reference implementation (NOTICE)
