# base32 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-03** — Audit: review and a 40-mutant run (38 killed, 2 equivalent). Four tests added
  for what the first pass left alive (lower-case `A`, tab and CR skipping, `decodeAlloc` on
  unpadded text); the module doc now points at the right SPEC section. No behaviour change.
- **2026-09-30** — New module: RFC 4648 base32 and base32hex codec with strict
  decoding (exact padding, canonical trailing bits) and opt-in lenient options;
  verified against the RFC §10 vectors and Python-stdlib encodings.
