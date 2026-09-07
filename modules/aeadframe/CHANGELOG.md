# aeadframe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz: `Opener.open`'s harness never ran a record. It drew
  `smith.bytes(&buf)` and then a ranged length, which reads eight octets as a
  little-endian u64 and returns the range minimum when fewer remain — so the
  length was always 0 and, with no corpus, the target ran `open(&out, "", "aad")`
  and nothing else, for ever. `record.parse` refuses that as `Truncated`, so the
  harness's own assertion (`m + record.overhead <= len`) had never executed.
  Now a single `smith.slice(&buf)` draw plus an 8-seed corpus built from this
  module's own sealer (a genuine record, the empty-plaintext minimum, one that
  fills the buffer, and four one-octet perturbations reaching `UnsupportedVersion`,
  `EpochMismatch`, `Truncated` and the Poly1305 refusal). Pinned by a corpus
  guard: 7 of 8 seeds non-empty, 3 accepted, 104 plaintext octets recovered.

- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on IPsec ESP
  (RFC 4303) / DTLS 1.3 record layer (design reference, not a test anchor).
- **2026-07-24** — New module: Per-key AEAD record layer — seal/open with a monotonic
  counter nonce (never reused), epoch rekey, sliding-window anti-replay + AAD binding;
  generic over the AEAD.
