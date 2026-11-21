# encoding

**Code page ↔ UTF-8** transcoding (the "iconv" job): every encoding of the
WHATWG Encoding Standard — all single-byte encodings, UTF-8, UTF-16 (LE/BE),
the CJK encodings (`encoding.cjk`) and `replacement` — plus UTF-32 and the DOS
pages CP437/850/852, with BOM sniffing, streaming decoders and encoders, fatal
mode and WHATWG semantics throughout. Internal currency everywhere else is
always UTF-8; this module only runs at the read edge (decode → UTF-8) and the
write edge (encode ← UTF-8).

- **Model after:** WHATWG Encoding Standard.
- **Platform:** any (pure logic, no OS calls). **Role:** codec.
  **Concurrency:** reentrant (no shared state — the tables are `const`).

Provenance: original work of the zig-libs authors (MIT) — no third-party
source code. Tests are anchored against vendored third-party normative DATA
(the WHATWG Encoding Standard's `index-*.txt` tables and Unicode.org's
`8859-1.TXT`); see `modules/encoding/NOTICE` for the attribution that data
carries.

## Supported encodings

The table lists the original five pages and `utf8`; the same `Encoding` enum
also holds the other 24 WHATWG single-byte pages, `x_user_defined` and the DOS
pages (see API below).

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
// original ones) plus utf8, x_user_defined and the DOS pages cp437/cp850/cp852
// (IANA labels, not WHATWG).
pub const Encoding = enum { utf8, windows_1250, windows_1252, iso_8859_1, iso_8859_2, iso_8859_15, ibm866, koi8_r, windows_1251, … };
fn Encoding.parse(s: []const u8) ?Encoding;          // case-insensitive, every WHATWG label + a few extras
fn Encoding.canonicalName(self) []const u8;          // "windows-1250", lower case
fn Encoding.whatwgName(self) []const u8;             // "KOI8-R", the Standard's spelling
fn lookupLabel(s) ?LabelTarget;                      // .encoding / .utf16 / .replacement / .cjk ("Shift_JIS")

fn decodeToUtf8(alloc, bytes: []const u8, enc: Encoding) ![]u8;   // caller owns result
fn encodeFromUtf8(alloc, utf8: []const u8, enc: Encoding) ![]u8;  // caller owns result; unmappable -> '?'
fn encodeFromUtf8Opts(alloc, utf8, enc, .{ .unmappable = .html_ncr }) ![]u8; // or .ignore / .fatal (error.Unmappable)

// UTF-16, BOM, streaming, fatal
fn decode(alloc, bytes, fallback: Encoding) !Decoded;           // WHATWG "decode": a BOM wins and is removed
fn sniffBom(bytes) ?Bom;                                         // .utf8 / .utf16le / .utf16be (WHATWG: ff fe 00 00 is UTF-16LE)
fn decodeUtf16(alloc, bytes, endian: Utf16Endian) ![]u8;
fn encodeUtf16(alloc, utf8, endian: Utf16Endian, bom: bool) ![]u8;
fn decodeFatal(alloc, bytes, kind: Decoder.Kind) ![]u8;         // error.Malformed instead of U+FFFD

var d: Decoder = .init(.{ .encoding = .windows_1250 }, .{});    // or .{ .utf16 = .le }; .fatal = true
try d.feed(alloc, &out, chunk);                                  // any chunking: split sequences carry over
try d.finish(alloc, &out);                                       // end of stream

// UTF-32 (Python utf-32 / x/text utf32), helpers, custom pages
fn decodeUtf32(alloc, bytes, endian: Utf32Endian) ![]u8;         // malformed unit / cut tail = one U+FFFD each
fn encodeUtf32(alloc, utf8, endian: Utf32Endian, bom: bool) ![]u8;
fn detect(bytes, more_follows: bool) Detection;                    // .utf8_bom/.utf16le_bom/.utf16be_bom/.ascii/.utf8/.unknown (never guesses legacy pages)
fn sniffBom32(bytes) ?Bom;                                       // + .utf32le (ff fe 00 00) / .utf32be (00 00 fe ff)
fn decode32(alloc, bytes, fallback: Encoding) !Decoded;          // `decode` that honours a UTF-32 BOM too
// Decoder/Encoder .init(.{ .utf32 = .le }, .{ .bom = true })
fn utf8ValidUpTo(s) usize;  fn isAscii(s) bool;  fn asciiValidUpTo(s) usize;   // vector
fn latin1ToUtf8(alloc, bytes) ![]u8;  fn utf8ToLatin1Lossy(alloc, utf8) ![]u8; // identity page, not windows-1252
const Toy = encoding.Custom(my_decode_table);                    // comptime [128]u16, 0xFFFF = hole
fn decodeCustom(alloc, bytes, Toy) ![]u8;  fn encodeCustom(alloc, utf8, Toy, .question_mark) ![]u8;

// caller-buffer core (no allocation) and the streaming encoder
const p = d.decodeInto(src, dst, last);       // Progress{ .status = .input_empty / .output_full / .malformed, .read, .written }
var e: Encoder = .init(.{ .encoding = .windows_1250 }, .{ .unmappable = .question_mark });
const q = e.encodeInto(cell, buf, true);      // reuse `buf` per cell; e.maxEncodedLen(n) sizes it
try e.feed(alloc, &out, chunk); try e.finish(alloc, &out);
```

**UTF-16 and UTF-32 are not `Encoding` members, on purpose.** Every `Encoding` maps bytes
below 0x80 to ASCII, which is what lets a caller transcode a CSV cell by cell and
write the delimiters as raw bytes. In UTF-16 `,` is `2c 00`, so UTF-16 has its own
entry points and cannot be selected through `Encoding.parse` or an enum listing.
An Excel "Unicode Text" export (UTF-16LE with `ff fe`) is read with
`decode(alloc, bytes, fallback)`.

**Data-lenient — never traps.** `decodeToUtf8` returns **valid UTF-8
unconditionally**: from a legacy page structurally (a byte the Standard leaves
undefined, as in windows-1253 or ISO-8859-8, becomes U+FFFD),
and from `.utf8` because malformed input is replaced with U+FFFD — one per
**maximal subpart** of an ill-formed sequence, WHATWG's decoder error mode (`e2 82`
is one U+FFFD). On encode, a codepoint with no representation in the target
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

**Speed:** `zig build bench-encoding` compares against encoding_rs and Go
x/text; the figures are on the module's catalog card (Performance line). ASCII
runs are handled in wide blocks, a single-byte page goes through a precomputed
UTF-8 table and a two-level reverse table, and UTF-8 is validated by the
Keiser–Lemire vector algorithm (port of simdjson's, NOTICE).

## CJK (`encoding.cjk`)

Shift_JIS, EUC-JP, ISO-2022-JP, EUC-KR, gb18030, GBK and Big5, exactly as the
Standard defines them (GB18030-2022 included). They are not ASCII-compatible
(trail bytes 0x40–0x7E), so they are not `Encoding` members: `cjk.Decoder`,
`cjk.Encoder`, `cjk.decodeToUtf8`, `cjk.encodeFromUtf8`, same shapes as the
single-byte API; `lookupLabel("sjis")` answers `.cjk = .shift_jis`. Their
~300 KB of tables are compiled only into a program that references
`encoding.cjk` (owner's `-Dcjk` intent, without a build option — the
`tz.full` precedent). Anchors: every vendored WHATWG index pointer, and
golang.org/x/text over 6.4 M cases with every divergence assigned to the
Standard rule that decides it (x/text lags GB18030-2022).

## Not provided

Statistical encoding detection (BOM sniffing only), Unicode normalization,
IDNA, UTF-7 (WHATWG maps it to `replacement`), EBCDIC and the further DOS pages:
see `SPEC.md` "What is deliberately not done".

## Verify

```
scripts/modtest encoding
```

Every high-table entry of the five original pages (128 bytes × 5 code pages =
640 byte/codepoint pairs) is cross-checked in both directions against the
vendored normative tables in `src/testdata/` (`normative_test.zig`); every other
page's table equals its vendored WHATWG index (`sb_tables_test.zig`). UTF-8,
UTF-16 and UTF-32 decoding (whole buffer, at every split point, byte by byte,
fatal) is checked against CPython's codecs (`tools/codec-oracle.py`, golden in
`src/testdata/codec_golden.txt`), labels and encodable code points against Go's
x/text, the CJK encodings against every vendored index pointer and x/text. Fuzz
harnesses run under `ENCODING_FUZZ`. See `SPEC.md` "Verification" and
`modules/encoding/NOTICE`.
