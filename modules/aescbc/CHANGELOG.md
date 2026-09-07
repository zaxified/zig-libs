# aescbc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz: `fuzzUnpad` had never executed one of its assertions.
  It drew `valueRangeAtMost(u16, 0, 512)` *before* the bytes, and a ranged draw
  returns the range minimum when fewer than eight octets remain — so `len` was 0
  on every input and, with no corpus, the target ran `unpadPkcs7("")` /
  `unpadXmlEnc("")` and nothing else. Both refuse an empty buffer at the first
  line, so neither invariant block was ever entered; the comment claiming "length
  drawn first so every mutated byte lands inside `data`" was false when written.
  Now one `smith.slice(&buf)` draw plus an 8-seed corpus. Pinned by a corpus
  guard: 7 of 8 seeds non-empty, 3 PKCS#7 accepts, 4 XML-Enc accepts (the extra
  one is the seed that separates the two schemes — a valid length byte behind 15
  octets that are not pad), 42 unpadded octets recovered.

- **2026-08-06** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Byte-exact vs NIST SP800-38A
  Appendix F.2.1 (AES-128-CBC) and F.2.5 (AES-256-CBC), *both directions independently
  asserted*.
- **2026-07-22** — New module: raw AES-CBC (NIST SP800-38A, over `std.crypto.core.aes`)
  + PKCS#7 / XML-Enc padding helpers; zero-alloc core, padding-oracle caveat documented
  (consumers own authenticate-before-unpad).
