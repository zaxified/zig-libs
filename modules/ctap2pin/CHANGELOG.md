# ctap2pin — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Test-only, no production change: `fuzzTwoDecrypt` had never decrypted
  anything. `cipher_len` came from `smith.valueRangeAtMost(u16, 0, 256)` drawn after
  `smith.bytes` had eaten the input; a ranged `Smith` draw returns the range MINIMUM when
  fewer than eight octets remain, so it was **0** on every input the ordinary lane ever ran,
  and `Two.decryptedLength(0)` returned `InvalidLength` before a single AES round. Now one
  `smith.slice(&cipher_buf)`, with a corpus that walks the length gate `Two.decrypt`
  actually has: `16 + 16k` accepted, 15 (short of the IV) and 33 (not a whole number of
  blocks) refused. Measured by the new `corpus:` guard: 6 non-empty seeds, 4 accepted
  lengths, **288 plaintext octets out of AES** (0 before). Octets rather than accepted
  lengths alone, because `decryptedLength(16)` is a legal 0 - an accepted length does not
  mean anything was decrypted.

- **2026-07-18** — Security audit: no findings. Modeled on `libfido2` (design reference,
  not a test anchor).
- **2026-07-12** — New module: CTAP2 `pinUvAuthProtocol` (FIDO2 / WebAuthn CTAP 2.1).
