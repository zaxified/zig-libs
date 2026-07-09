# encoding

Legacy single-byte **code page ↔ UTF-8** transcoding (the "iconv" job) for the
five European code pages a legacy broker / Excel export is realistically saved
in. Internal currency everywhere else is always UTF-8; this module only runs at
the read edge (decode → UTF-8) and the write edge (encode ← UTF-8).

- **Status:** `extract` — lifted from bxp `bxp-core/src/encoding.zig`.
- **Model after:** WHATWG Encoding Standard (the single-byte European subset).
- **Platform:** any (pure logic, no OS calls). **Role:** codec.
  **Concurrency:** reentrant (no shared state — the tables are `const`).

Provenance: extracted from bxp `bxp-core/src/encoding.zig` (same author, MIT).
This is the WHATWG **single-byte European subset**; full WHATWG coverage
(the other single-byte pages + all multi-byte/CJK) is deferred (see below). No
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

## Deferred (future Fable pass)

Full WHATWG Encoding Standard coverage. The `build(&overrides)` table pattern
generalizes trivially — the remaining work is *sourcing the correct per-encoding
mapping tables* from the spec, not new logic:

- **Other single-byte pages:** windows-1251/1253–1258, KOI8-R/U,
  ISO-8859-3..14/16.
- **Multi-byte / CJK:** Shift-JIS, EUC-JP, GBK/GB18030, Big5.
- **UTF-16:** UTF-16LE / UTF-16BE (with BOM sniffing).

## Verify

```
zig build test-encoding
```
