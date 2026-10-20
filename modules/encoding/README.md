# encoding

Legacy single-byte **code page ↔ UTF-8** transcoding (the "iconv" job) for the
five European code pages a legacy broker / Excel export is realistically saved
in. Internal currency everywhere else is always UTF-8; this module only runs at
the read edge (decode → UTF-8) and the write edge (encode ← UTF-8).

- **Model after:** WHATWG Encoding Standard (the single-byte European subset).
- **Platform:** any (pure logic, no OS calls). **Role:** codec.
  **Concurrency:** reentrant (no shared state — the tables are `const`).

Provenance: original work of the zig-libs authors (MIT) — no third-party
source code. Tests are anchored against vendored third-party normative DATA
(the WHATWG Encoding Standard's `index-*.txt` tables and Unicode.org's
`8859-1.TXT`); see `modules/encoding/NOTICE` for the attribution that data
carries.
This is the WHATWG **single-byte European subset** plus, since 2026-10-04,
**UTF-16** (LE/BE), **BOM sniffing**, a **streaming** decoder and a **fatal**
mode — WHATWG semantics throughout. Other single-byte pages and CJK stay out
of scope — see below.

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
bytes (delimiters, quotes, CR, LF) survive transcoding. ⚠ *Delimiters*, not
*positions*: decode expands up to 3x (4 MiB of `0x80` as windows-1250 is
12 MiB), so an earlier "raw byte offsets stay valid" here was false as
written — what holds is that a framer running on the RAW bytes still finds
its delimiters. The high half (0x80–0xFF) is built from an identity base (Latin-1 /
C1) plus per-page override tables.

## API

```zig
const encoding = @import("encoding");

// Every WHATWG single-byte encoding (29 pages; the first five tags are the
// original ones) plus utf8. 2026-10-20.
pub const Encoding = enum { utf8, windows_1250, windows_1252, iso_8859_1, iso_8859_2, iso_8859_15, ibm866, koi8_r, windows_1251, … };
fn Encoding.parse(s: []const u8) ?Encoding;          // case-insensitive, every WHATWG label + a few extras
fn Encoding.canonicalName(self) []const u8;          // "windows-1250", lower case
fn Encoding.whatwgName(self) []const u8;             // "KOI8-R", the Standard's spelling
fn lookupLabel(s) ?LabelTarget;                      // .encoding / .utf16 / .replacement / .x_user_defined / .unsupported ("Shift_JIS")

fn decodeToUtf8(alloc, bytes: []const u8, enc: Encoding) ![]u8;   // caller owns result
fn encodeFromUtf8(alloc, utf8: []const u8, enc: Encoding) ![]u8;  // caller owns result; unmappable -> '?'
fn encodeFromUtf8Opts(alloc, utf8, enc, .{ .unmappable = .html_ncr }) ![]u8; // or .ignore / .fatal (error.Unmappable)

// 2026-10-04: UTF-16, BOM, streaming, fatal
fn decode(alloc, bytes, fallback: Encoding) !Decoded;           // WHATWG "decode": a BOM wins and is removed
fn sniffBom(bytes) ?Bom;                                         // .utf8 / .utf16le / .utf16be
fn decodeUtf16(alloc, bytes, endian: Utf16Endian) ![]u8;
fn encodeUtf16(alloc, utf8, endian: Utf16Endian, bom: bool) ![]u8;
fn decodeFatal(alloc, bytes, kind: Decoder.Kind) ![]u8;         // error.Malformed instead of U+FFFD

var d: Decoder = .init(.{ .encoding = .windows_1250 }, .{});    // or .{ .utf16 = .le }; .fatal = true
try d.feed(alloc, &out, chunk);                                  // any chunking: split sequences carry over
try d.finish(alloc, &out);                                       // end of stream

// 2026-10-20: caller-buffer core (no allocation) and the streaming encoder
const p = d.decodeInto(src, dst, last);       // Progress{ .status = .input_empty / .output_full / .malformed, .read, .written }
var e: Encoder = .init(.{ .encoding = .windows_1250 }, .{ .unmappable = .question_mark });
const q = e.encodeInto(cell, buf, true);      // reuse `buf` per cell; e.maxEncodedLen(n) sizes it
try e.feed(alloc, &out, chunk); try e.finish(alloc, &out);
```

**UTF-16 is not an `Encoding` member, on purpose.** Every `Encoding` maps bytes
below 0x80 to ASCII, which is what lets a caller transcode a CSV cell by cell and
write the delimiters as raw bytes. In UTF-16 `,` is `2c 00`, so UTF-16 has its own
entry points and cannot be selected through `Encoding.parse` or an enum listing.
An Excel "Unicode Text" export (UTF-16LE with `ff fe`) is read with
`decode(alloc, bytes, fallback)`.

**Data-lenient — never traps.** `decodeToUtf8` returns **valid UTF-8
unconditionally**: from a legacy page structurally (a byte the Standard leaves
undefined, as in windows-1253 or ISO-8859-8, becomes U+FFFD),
and from `.utf8` because malformed input is replaced with U+FFFD — one per
**maximal subpart** of an ill-formed sequence, WHATWG's decoder error mode (since
2026-10-04; before it was one per byte, so `e2 82` was two U+FFFD, now one). On encode, a codepoint with no representation in the target
page becomes `'?'`, and invalid/truncated UTF-8 passes through verbatim
byte-for-byte, resynchronising **one byte at a time** so a delimiter right
after bad input is never swallowed. Neither direction ever errors on content
(only on allocation failure).

⚠ **One deliberate departure from WHATWG**, worth knowing before relying on
either behaviour: WHATWG maps the labels `iso-8859-1` / `latin1` to the
**windows-1252** encoding, because that is what the web contains. Here they
select `iso_8859_1`, the true ISO/IEC 8859-1 page. `\x93quoted\x94` is
`“quoted”` in a browser and a pair of C1 controls here. Pass `.windows_1252`
explicitly for web-sourced data. Every other label in the WHATWG table is
accepted, and leading/trailing whitespace is stripped.

**Speed (2026-10-20):** 0.36–1.06× encoding_rs 0.8.42 over 14 rows
(`zig build bench-encoding`): ASCII runs 32 bytes at a time, a single-byte
page through a precomputed UTF-8 table and a two-level reverse table, UTF-8
validated by the Keiser–Lemire vector algorithm (port of simdjson's, NOTICE).

## Out of scope (not planned)

CJK multi-byte encodings (Shift_JIS, EUC-JP, ISO-2022-JP, EUC-KR, GBK/GB18030,
Big5) are decided (owner 2026-10-20) but not built yet: they come behind a
build option `-Dcjk`, so only a consumer that enables it pays their tables.
`lookupLabel` already names them (`.unsupported`).

## Verify

```
zig build test-encoding
```

UTF-8 and UTF-16 decoding (whole buffer, at every split point, byte by byte,
fatal) and UTF-16 encoding are checked against CPython's codecs on 5 669 cases
(`tools/codec-oracle.py`, golden in `src/testdata/codec_golden.txt`).

Every high-table entry (128 bytes × 5 code pages = 640 byte/codepoint pairs)
is cross-checked in both directions (decode and encode) against the vendored
normative tables in `src/testdata/` — see `normative_test.zig` and
`modules/encoding/NOTICE`.
