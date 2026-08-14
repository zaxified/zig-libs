# bolt3 — SPEC

## Scope

BOLT#3 key derivation, the secp256k1 crypto pocket of the Lightning commitment
scheme. Two constructions from the "Key Derivation" section plus the Appendix D
per-commitment secret generation that sources them.

## Design & framing

- **Simple per-commitment derivation** blinds a static basepoint with
  `SHA256(per_commitment_point ‖ basepoint)`: the public form adds `h·G` to the
  basepoint; the secret form adds `h` to the basepoint secret mod n. Used for
  `localpubkey`, `*_delayedpubkey`, `*_htlcpubkey` and their secrets.
- **Revocation derivation** is a two-term blinded sum
  `rb·SHA256(rb‖pcp) + pcp·SHA256(pcp‖rb)`, engineered so the revocation secret
  requires one secret from *each* party — the primitive behind the justice
  transaction that penalizes a revoked-state broadcast.
- **Per-commitment secret generation** (Appendix D) is the hash tree
  `generate_from_seed`: from the seed, for each set bit of the 48-bit index from
  bit 47 down to 0, flip that bit of the running value and SHA-256 it. Forward-
  derivable, not backward — the property the whole revocation scheme relies on.
- Hash-to-scalar reduction reuses the repo's `bip340` idiom (widen to 48 bytes,
  wide-reduce mod n) so a hash value ≥ n is never rejected.

## Threat model

Not a parser of untrusted wire data — inputs are keys/secrets a channel peer
already holds. Invalid 33-byte points and non-canonical/zero 32-byte secrets
surface as typed errors (`InvalidPoint` / `InvalidSecret`), never panics; a
derivation landing on the identity element surfaces as `IdentityElement`
(statistically impossible for honest inputs). No secret-dependent branching
beyond `std.crypto.ecc`'s constant-time scalar ladder.

## Verification

- BOLT#3 **Appendix E** — all four vectors (key and revocation, public and
  secret) byte-exact.
- BOLT#3 **Appendix D** — all five `generate_from_seed` generation vectors
  byte-exact.
- Cross-checks: each derived secret's public point equals the independently
  derived public key; a real shachain secret feeds the revocation derivation.
- Green in Debug + ReleaseFast.

## Backlog / deferred

- **App D storage half** — `RevocationStore`: the O(48)-element compact store of
  received per-commitment secrets with derived-child consistency validation
  (BOLT#3 Appendix D *storage* vectors). Smaller crypto, more data structure.
- **Commitment / HTLC transaction construction** — the non-crypto serialization
  (to_local/to_remote/HTLC outputs, scripts, feerate math). Opus/Sonnet, not a
  Fable pocket.

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** BOLT#3 Appendix D/E official test vectors, byte-exact (NOTICE)
