# encoding — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Legacy single-byte code page ↔ UTF-8 transcoding for the five European code pages a legacy broker /
Excel export is realistically saved in (`windows_1250`, `windows_1252`, `iso_8859_1`, `iso_8859_2`,
`iso_8859_15`, plus `utf8` pass-through). `Encoding.parse` is case-insensitive with common aliases
(`cp1250`, `latin-1`, etc.); `decodeToUtf8`/`encodeFromUtf8` take an allocator and return an owned
buffer. Each page's low half (0x00–0x7F) is ASCII and maps to itself, so structural bytes
(delimiters, quotes, CR, LF) survive transcoding and raw byte offsets stay valid; the high half
(0x80–0xFF) is built from an identity Latin-1/C1 base plus per-page override tables. This module
runs only at the read edge (decode → UTF-8) and the write edge (encode ← UTF-8) — internal currency
everywhere else is always UTF-8. Platform: any (pure logic, no OS calls). Role: codec. Concurrency:
reentrant (tables are `const`, no shared state). Modeled after the WHATWG Encoding Standard's
single-byte European subset; extracted from bxp `bxp-core/src/encoding.zig` (same author, MIT) — no
third-party code, no NOTICE entry beyond the standard's public definitions.

## Threat model / out of scope
**Data-lenient — never traps.** On decode, an unmappable codepoint falls back to the verbatim
source byte. On encode, a codepoint with no representation in the target page becomes `'?'`, and
invalid/truncated UTF-8 passes through verbatim byte-for-byte. Neither direction ever errors on
content (only on allocation failure) — so hostile/malformed input cannot crash or hang transcoding,
only silently degrade fidelity (which is the documented, deliberate contract, not a bug to fix).
Out of scope, intentionally not planned: broader WHATWG Encoding Standard coverage — other
single-byte pages (windows-1251/1253–1258, KOI8, ISO-8859-3..16), multi-byte/CJK (Shift-JIS, EUC-JP,
GBK/GB18030, Big5), and UTF-16. The `build(&overrides)` table pattern would generalize but there is
no in-house need beyond the European subset; reopen only on a concrete requirement.

## Verification
12 tests: round-trip decode/encode for all five code pages across the full high-half table,
ASCII-identity of the low half, alias parsing (case-insensitive + all listed aliases per page),
lenient-fallback behavior on unmappable codepoints (encode → `'?'`) and unmappable bytes (decode →
verbatim passthrough), and invalid/truncated UTF-8 passthrough on encode. Run: `zig build
test-encoding`.

## Backlog / deferred
Per PLAN.md (2026-07-09 extraction-scope note): broader/CJK coverage is explicitly out of scope, not
planned — no further backlog item recorded. The module README's "Out of scope" section is the
canonical statement of this boundary.

## Status
`extract · any · codec · reentrant` · deps: none — canonical source is `pub const meta` in
src/root.zig.
