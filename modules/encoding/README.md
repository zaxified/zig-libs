# encoding

Legacy single-byte **code page ↔ UTF-8** transcoding (the "iconv" job) for the
five European code pages a legacy broker / Excel export is realistically saved
in. Internal currency everywhere else is always UTF-8; this module only runs at
the read edge (decode → UTF-8) and the write edge (encode ← UTF-8).

- **Model after:** WHATWG Encoding Standard (the single-byte European subset).
- **Platform:** any (pure logic, no OS calls). **Role:** codec.
  **Concurrency:** reentrant (no shared state — the tables are `const`).

Provenance: original work of the zig-libs authors (MIT).
This is the WHATWG **single-byte European subset** — the deliberate, complete
scope of this module (the legacy code pages a European broker / Excel export is
realistically saved in). Broader coverage (other single-byte pages, multi-byte/
CJK, UTF-16) is intentionally **out of scope**, not planned — see below. No
third-party code.

## Supported encodings

| `Encoding`      | Name           | Aliases parsed                       |
|-----------------|----------------|--------------------------------------|
| `utf8`          | `utf-8`        | `utf8` (pass-through, the default)   |
| `windows_1250`  | `windows-1250` | `windows1250`, `cp1250`, `win1250`   |
| `windows_1252`  | `windows-1252` | `windows1252`, `cp1252`, `win1252`   |
| `iso_8859_1`    | `iso-8859-1`   | `iso8859-1`, `latin-1`, `latin1`     |
| `iso_8859_2`    | `iso-8859-2`   | `iso8859-2`, `latin-2`, `latin2`     |
| `iso_8859_15`   | `iso-8859-15`  | `iso8859-15`, `latin-9`, `latin9`    |

Each page's low half (0x00–0x7F) is ASCII and maps to itself, so structural
bytes (delimiters, quotes, CR, LF) survive transcoding and raw byte offsets
stay valid. The high half (0x80–0xFF) is built from an identity base (Latin-1 /
C1) plus per-page override tables.

## API

```zig
const encoding = @import("encoding");

pub const Encoding = enum { utf8, windows_1250, windows_1252, iso_8859_1, iso_8859_2, iso_8859_15 };
fn Encoding.parse(s: []const u8) ?Encoding;          // case-insensitive, aliases
fn Encoding.canonicalName(self) []const u8;

fn decodeToUtf8(alloc, bytes: []const u8, enc: Encoding) ![]u8;   // caller owns result
fn encodeFromUtf8(alloc, utf8: []const u8, enc: Encoding) ![]u8;  // caller owns result
```

**Data-lenient — never traps.** On decode, an unmappable codepoint falls back
to the verbatim source byte. On encode, a codepoint with no representation in
the target page becomes `'?'`, and invalid/truncated UTF-8 passes through
verbatim byte-for-byte. Neither direction ever errors on content (only on
allocation failure).

## Out of scope (not planned)

Broader WHATWG Encoding Standard coverage — other single-byte pages
(windows-1251/1253–1258, KOI8, ISO-8859-3..16), multi-byte/CJK (Shift-JIS,
EUC-JP, GBK/GB18030, Big5), and UTF-16 — is **intentionally not built**. The
`build(&overrides)` table pattern would generalize, but there is no in-house
need beyond the European subset; a project that must ingest CJK/Cyrillic legacy
text should handle that at its own edge. Reopen only on a concrete requirement.

## Verify

```
zig build test-encoding
```
