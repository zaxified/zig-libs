# base32 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — **Fixed (constant time): `encode` and `decode` no longer index a table or branch on the value of a symbol.** `encode` indexed the alphabet by each secret 5-bit group and `decode` ran every character through a 256-entry table and returned at the first invalid one; `otp` writes and reads TOTP secrets through them. Each symbol is now computed arithmetically (range decisions are borrows turned into masks, as in `sessions/src/idhex.zig`), and the validity of the decoded characters is accumulated as a mask with one error after the loop. API, results and error precedence are unchanged (left-to-right: the earliest of invalid character, misplaced padding, full buffer). Cross-checked in the tests against the old table implementation: every 5-bit value, every byte, both alphabets and cases, and 60,000 random texts including error kind. What still branches is public: the options, the lengths and whether a character is padding or skippable whitespace. ctgrind not run here.
- **2026-10-10** — tests: deterministic fuzz driver `BASE32_FUZZ` over the decode harness (generic over its choice source) plus a new encode/decode roundtrip oracle (genuine accepted, padding mode strict, a substituted symbol never decodes to the original). No code change.
- **2026-10-03** — Audit: review and a 40-mutant run (38 killed, 2 equivalent). Four tests added
  for what the first pass left alive (lower-case `A`, tab and CR skipping, `decodeAlloc` on
  unpadded text); the module doc now points at the right SPEC section. No behaviour change.
- **2026-09-30** — New module: RFC 4648 base32 and base32hex codec with strict
  decoding (exact padding, canonical trailing bits) and opt-in lenient options;
  verified against the RFC §10 vectors and Python-stdlib encodings.
