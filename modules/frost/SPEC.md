# frost — SPEC

FROST (Flexible Round-Optimized Schnorr Threshold signatures), RFC 9591,
**secp256k1/SHA-256 ciphersuite (§6.5) only**; see [README.md](README.md)
for purpose and API. Provenance: see [NOTICE](NOTICE).

**Status: scaffold.** Wire codecs, RFC §4.3 list operations, and the five
ciphersuite hash functions plus their pure-glue callers
(`computeChallenge`, `nonceGenerate`, `generateNonces`) are implemented
and cross-validated byte-exact against RFC 9591 Appendix E.5's published
intermediate values. The ten threshold-specific cryptographic cores are
`@panic("TODO(fable): ...")` stubs with fixed final signatures — see
"TODO(fable) — remaining" below.

## Design

- **Source of truth**: RFC 9591 (IRTF CFRG, June 2024), consumed directly
  from `https://www.rfc-editor.org/rfc/rfc9591.txt`. Only the
  secp256k1/SHA-256 ciphersuite (§6.5) is in scope — RFC 9591 also
  defines Ed25519 (§6.1), Ed448 (§6.3), ristretto255 (§6.2, the RFC's
  RECOMMENDED ciphersuite), and P-256 (§6.4); none of those are
  scaffolded here. A ristretto255 pass is a reasonable follow-up module
  but a SEPARATE one — different group, different `H1`..`H5`, different
  `Ne`/`Ns` — not an extension of this file.
- **`H1`/`H2`/`H3` are `hash_to_field`, NOT a BIP340-style tagged hash.**
  This is the single most-likely-to-be-gotten-wrong detail in this
  ciphersuite, worth restating outside `root.zig`'s doc comments too: RFC
  9591 §6.5 defines `H1(m) = hash_to_field(m, 1)` per RFC 9380 §5.2, with
  `expand_message_xmd`, SHA-256, `L = 48`, `DST = contextString ||
  "rho"` (similarly `"chal"` for `H2`, `"nonce"` for `H3`). This is a
  DIFFERENT hash construction from `bip340.taggedHash`'s `SHA256(SHA256
  (tag) || SHA256(tag) || msg)` — different preimage shape, different
  domain-separation mechanism (a length-prefixed DST folded into TWO
  compression-function calls via `expand_message_xmd`'s `b_0`/`b_1`/`b_2`
  chaining, not a simple midstate reuse), and a WIDE reduction
  (48 bytes → mod `p`, not a direct 32-byte parse). `H4`/`H5` ARE simple
  tagged SHA-256 (`SHA256(contextString || label || m)`, no
  `expand_message_xmd`) — do not confuse the two hash SHAPES within the
  same ciphersuite.
- **Validation of the hash layer**: RFC 9591's own Appendix E.5 vector
  does not publish an `expand_message_xmd`/`hash_to_field` KAT in
  isolation (RFC 9380 has its own separate vector suite for that, not
  embedded here), but it DOES publish `binding_factor_input` →
  `binding_factor` pairs (`H1` applied to a known 129-byte preimage) and
  `hiding_nonce_randomness`/`participant_share` → `hiding_nonce` triples
  (`H3` applied to a known 64-byte preimage) — both exercised byte-exact
  in `kat_test.zig`, which is a real, if indirect, `expand_message_xmd`
  KAT. `H2` shares the identical construction (only the DST label
  differs) and is validated only indirectly, through `round2Sign`'s
  signature-share equation matching the vector's `sig_share` once that
  core is implemented — see "what the vectors do NOT cover" below.
- **BIP340 compatibility — explicit finding: NO.** Restated from
  `root.zig`'s module doc comment (the single most important correctness
  fact for a reader of this module to internalize): this ciphersuite's
  elements are 33-byte SEC1-COMPRESSED points (not BIP340's 32-byte
  x-only/even-y), its signature is 65 bytes `(R, z)` (not BIP340's 64
  bytes `(r, s)`), and its challenge hash `H2` — both preimage shape
  (`33 + 33 + msg`, not `32 + 32 + msg`) AND construction
  (`expand_message_xmd`, not a BIP340 tagged hash) — differs from
  BIP340's. `verify` in this module implements RFC 9591 Appendix B's
  `prime_order_verify` directly; it does not call `bip340.verify`, and no
  amount of encode/decode glue bridges the two (the challenge hash
  itself is different, not just the wire format). The `bip340` build
  dependency exists only because the orchestrator wired every
  Schnorr-family module through it for a future cross-module comparison;
  no function in this module currently calls into `bip340`.
- **Type design — wire types vs. raw `Scalar`**: values that flow "over
  the wire" between participants/the Coordinator (`Identifier`,
  `SigningShare`, `VerifyingShare`/`GroupPublicKey`/`NonceCommitment`
  (all `Element`), `SignatureShare`, `SigningCommitments`, `Signature`)
  are bespoke byte-array-backed structs with `fromBytes`/`toBytes`
  performing RFC 9591's own `DeserializeScalar`/`DeserializeElement`
  validation. Values that are NEVER serialized (`SigningNonces` — RFC
  9591 §5.1: "The nonce value is secret and MUST NOT be shared"; the
  trusted dealer's `secret_key`/`coefficients` in `trustedDealerKeygen`)
  use the raw `Secp256k1.scalar.Scalar` type directly (re-exported as
  `frost.Scalar`), since there is no wire encoding to validate against.
- **`SigningShare`/`SignatureShare` share an identical wire shape** (both
  32-byte big-endian `Scalar`s) but are kept as NOMINALLY DISTINCT Zig
  types via the `ScalarWire(comptime tag: []const u8)` factory, so a call
  site cannot accidentally pass one where the other belongs despite the
  compiler seeing "just 32 bytes" in both cases.
- **Deterministic entry points, no internal RNG** (the task's own
  "critical correctness note", worth preserving here): `round1Commit`
  takes `SigningNonces` directly rather than generating them itself;
  `trustedDealerKeygen` takes `coefficients` directly rather than
  sampling them itself; `nonceGenerate`/`generateNonces` take
  `random_bytes` as an explicit parameter rather than reading a global
  RNG. This is what makes every one of these replayable against RFC 9591
  Appendix E.5's fixed vector — a real deployment's caller is
  responsible for sourcing fresh secure randomness for the `..._random`/
  `coefficients` inputs (see `Secp256k1.scalar.random`/`std.Io`).
- **`Ne = 33`, `Ns = 32`** (RFC 9591 §6.5) are exported as named
  constants (`frost.Ne`, `frost.Ns`) rather than inlined as magic numbers
  throughout — every wire type's `encoded_length` derives from them.
- **Allocator usage**: functions whose output/scratch space scales with
  the number of participants (`computeBindingFactors`,
  `participantsFromCommitmentList`, `encodeGroupCommitmentList`,
  `round2Sign`, `aggregate`, `verifySignatureShare`,
  `trustedDealerKeygen`) take an explicit `allocator: std.mem.Allocator`
  parameter (CONVENTIONS.md §1 item 2: "caller-supplied allocators, no
  hidden globals") — NONE of them reach for a global/page allocator.
  Functions whose output is O(1) regardless of participant count
  (`computeGroupCommitment`, `deriveInterpolatingValue`, `round1Commit`,
  `verify`, `computeChallenge`, `h1`..`h5`, `nonceGenerate`,
  `generateNonces`, `bindingFactorForParticipant`) take no allocator.
- **What the vectors do NOT cover**: RFC 9591 Appendix E.5's secp256k1
  vector does not publish a standalone `group_commitment` or `challenge`
  scalar (unlike `binding_factor_input`/`binding_factor`, which ARE
  published per-signer). This is confirmed by direct reading of the RFC
  text, not an oversight in transcription. Consequently
  `computeGroupCommitment` is checked only via `aggregate`'s `R` output
  matching the vector's published `sig`'s first 33 bytes, and
  `computeChallenge`/`h2` is checked only via `round2Sign`'s
  signature-share equation reproducing the vector's published
  `sig_share` byte-exact (both are complete, correct checks — just
  indirect ones, composed rather than isolated).

## Threat model

- **Signing-share secrecy** (`SigningShare`, `SigningNonces`): the
  central secret this scheme protects is the group secret `s` — no
  single participant's `sk_i` (nor, before combination, any
  `MIN_PARTICIPANTS - 1`-sized subset of them) should leak `s` or enable
  forging a signature. This is Shamir's information-theoretic guarantee,
  not something the Zig implementation can strengthen or weaken by
  itself — but the implementation MUST NOT introduce a side channel that
  leaks `sk_i`/nonce values through timing (RFC 9591 §7.1 "Side-Channel
  Mitigations" — the same category of concern `bip340`'s doc comments
  flag for `d`/`k`). `Secp256k1.scalar`'s field ops are std's own
  constant-time implementation; this module introduces no additional
  branches on secret scalars in its REAL code (the stubbed cores are
  where a future pass must uphold this — each doc comment flags which
  operands are secret).
- **Nonce reuse** (RFC 9591 §7.3 "Nonce Reuse Attacks"): reusing a
  `(hiding_nonce, binding_nonce)` pair across two `round2Sign` calls for
  the same participant is a KEY-RECOVERY vulnerability (classic
  Schnorr/ECDSA nonce-reuse linear-algebra attack, generalized to the
  threshold setting) — RFC 9591 §5.2 states this as a MUST NOT. This
  module cannot enforce "used exactly once" at the type level (a
  `SigningNonces` value has no built-in single-use marker); a caller
  integrating this module is responsible for deleting/never reusing a
  nonce pair after one `round2Sign` call, exactly as the RFC's own prose
  requires of the CALLER, not the primitive.
- **Identifiable abort / misbehaving participants** (RFC 9591 §5.4):
  FROST provides no robustness — one dishonest signer contributing a bad
  share can only be detected (via `verifySignatureShare`), not tolerated.
  This module exposes `verifySignatureShare` precisely so a Coordinator
  CAN implement this detection; it does not itself decide what to do
  about a misbehaving participant (out of scope, same as the RFC's own
  stance).
- **Trusted dealer** (RFC 9591 Appendix C, `trustedDealerKeygen`): the
  dealer must generate good randomness, delete `secret_key`/
  `secret_key_shares` after distribution, and keep them confidential
  until distributed — this module's `trustedDealerKeygen` does not (and
  cannot) enforce any of that; it is a pure computation. A production
  deployment wanting to avoid a single trusted dealer needs a distributed
  key-generation protocol, which is explicitly out of scope for RFC 9591
  itself (and hence for this module).
- **`verify`/`verifySignatureShare` never panic on adversarial input** —
  both return `bool`/error unions distinguishing "malformed input" from
  "well-formed but doesn't verify," and NEITHER treats "doesn't verify"
  as an error condition (mirrors `bip340.verify`'s own convention) —
  important for a Coordinator that must keep running after rejecting one
  bad share, not abort the whole process.

## Out of scope

- Ristretto255/Ed25519/Ed448/P-256 ciphersuites (RFC 9591 §6.1-§6.4) —
  each needs its own module (different group/hash/`Ne`/`Ns`).
- Distributed key generation (an alternative to Appendix C's trusted
  dealer) — RFC 9591 does not specify one; out of scope by the RFC's own
  admission, hence out of scope here.
- Feldman VSS SHARE VERIFICATION (`vss_verify`, Appendix C.2) —
  `trustedDealerKeygen` returns `vss_commitment`, which a caller can
  independently check a share against via `vss_verify`'s formula
  (`S_i == sum(vss_commitment[j] * i^j)`), but this module does not
  itself expose a `vssVerify` helper in this scaffolding pass. A
  reasonable, small follow-up.
- Distributed/removed-Coordinator deployment shapes (RFC 9591 §7.5) — the
  Coordinator role here is left to the caller/consumer, same as the RFC's
  own framing (this module supplies the per-role FUNCTIONS, not a
  network protocol or role-assignment policy).

## TODO(fable) — remaining

The ten threshold-specific cryptographic cores, each a
`@panic("TODO(fable): ...")` stub in `root.zig` with a fixed final
signature and a doc comment spelling out the exact RFC 9591 construction:

- `deriveInterpolatingValue` (§4.2) — the Lagrange coefficient at `x=0`.
  THE threshold-specific primitive; everything else built on top of it
  is "ordinary" (n-of-n) Schnorr math.
- `computeBindingFactors` (§4.4) — the anti-forgery construction tying
  each signer's binding nonce to the whole commitment set.
- `computeGroupCommitment` (§4.5) — sums each signer's
  `hiding_nonce_commitment + binding_factor * binding_nonce_commitment`.
- `round1Commit` (§5.1's public-commitment half) — `ScalarBaseMult` of
  each supplied nonce.
- `round2Sign` (§5.2) — the signature-share equation:
  `hiding_nonce + binding_nonce*binding_factor + lambda_i*sk_i*challenge`.
- `aggregate` (§5.3) — `R = computeGroupCommitment(...)`,
  `z = sum(sig_shares)`.
- `verifySignatureShare` (§5.3) — the per-share verification equation.
- `verify` (Appendix B `prime_order_verify`) — the aggregate-signature
  verification equation (NOT `bip340.verify` — see "BIP340 compatibility"
  above).
- `trustedDealerKeygen` / `secretShareCombine` (Appendix C) — Shamir
  split (`secret_share_shard` + `vss_commit`) and combine
  (`secret_share_combine` via `polynomial_interpolate_constant`).

Once filled in, `kat_test.zig`'s existing assertions (already written
against each core's fixed final signature) become the acceptance check —
no test-file changes should be needed, only `root.zig`'s stub bodies.
