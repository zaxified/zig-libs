# jsontext — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-08** — **NEW MODULE:** `jsontext` — `writeString` / `writeStringContents` (JSON string literal from arbitrary bytes; ill-formed UTF-8 as U+FFFD per maximal subpart, byte escapes or an error; optional ASCII-only and HTML-safe output) and `depthWithin` (string-aware nesting prescan). The writer is `accesslog`'s table-driven escaper moved here unchanged for the default options; other consumers (framing, mcp, jsonshape, health, openapi …) move onto it in a later wave.
