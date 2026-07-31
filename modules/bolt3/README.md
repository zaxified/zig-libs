# bolt3

BOLT#3 Schnorr-free **key derivation** — the secp256k1 crypto pocket of the
Lightning commitment scheme. This module covers exactly two constructions from
the BOLT#3 spec plus the per-commitment secret source that feeds them; the
surrounding commitment-transaction / HTLC-output serialization (non-crypto) is
deliberately out of scope for this pass.

Provenance: clean-room from BOLT#3 (`lightning/bolts`), a public specification;
the secp256k1 group comes from the sibling [`k256`](../k256) module. Full
provenance detail — including why no third-party Lightning source was consulted
— is in this module's own [`NOTICE`](NOTICE); it carries no condition beyond
zig-libs' MIT license.

## What it does

| Function | BOLT#3 section |
|---|---|
| `derivePublicKey` / `derivePrivateKey` | Per-commitment blinding: `basepoint + SHA256(per_commitment_point ‖ basepoint)·G` (and the secret mod n) |
| `deriveRevocationPublicKey` / `deriveRevocationPrivateKey` | Revocation split-secret: `rb·SHA256(rb‖pcp) + pcp·SHA256(pcp‖rb)` — the justice-transaction primitive that neither party alone can complete |
| `perCommitmentSecret(seed, index)` | Appendix D shachain generation: the O(48) hash tree the secrets are drawn from |

Points are 33-byte SEC1-compressed; secrets are 32-byte big-endian scalars.

## Scope

- **In:** the four App E key derivations + App D per-commitment secret *generation*.
- **Out (follow-up):** App D *storage* (`RevocationStore` — compact receipt of
  revealed secrets with derived-child consistency checks); commitment/HTLC
  transaction construction and scripts (non-crypto, a later non-Fable pass,
  mirroring how `ssh` shipped its transport crypto first).

## Verification

Byte-exact against the official BOLT#3 test vectors: **Appendix E** (all four
base/revocation × public/secret derivations) and **Appendix D** (all five
`generate_from_seed` generation vectors), plus cross-checks that each derived
secret's public point equals the independently derived public key, and that a
real shachain secret feeds the revocation derivation end-to-end. Green in
Debug + ReleaseFast.

## Dependencies

std only — `std.crypto.ecc.Secp256k1` (curve group) and
`std.crypto.hash.sha2.Sha256`. No third-party crypto.
