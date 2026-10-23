# encoding — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-23** — Fix: `decodeUtf8`/`validPrefix` failed to compile for a target without AVX2 in an optimized mode (x86_64-windows baseline, `ReleaseSmall`: "evaluation exceeded 1000 backwards branches" in the portable lookup tree); `scan` raises its branch quota.
- **2026-10-20** — CJK speed: inline two-byte fast paths in the Shift_JIS/EUC-KR/gb18030/GBK/Big5/ISO-2022-JP decoders, two-level code-point maps in the encoders (+49–73 KB per encoding family, only when referenced). Bench vs encoding_rs 0.09–1.10× over all 25 rows.
- **2026-10-20** — **NO CONSUMER-VISIBLE CHANGE:** bench rows for the CJK encodings (decode/encode Shift_JIS, EUC-KR, gb18030, Big5, ISO-2022-JP; streaming Shift_JIS) — tools only.
- **2026-10-20** — `encoding.cjk`: Shift_JIS, EUC-JP, ISO-2022-JP, EUC-KR, gb18030, GBK, Big5 (WHATWG,
  GB18030-2022), decoders/encoders in the caller-buffer shape, tables generated from vendored WHATWG
  indexes (`tools/gen_cjk_tables.py`), x/text oracle. **Behavioural:** `LabelTarget.unsupported` is
  replaced by `.cjk`. CJK fuzz harness.
- **2026-10-20** — S2 parity, small items (R9-R12, R15). UTF-32 LE/BE (`decodeUtf32`, `encodeUtf32`,
  `Decoder.Kind`/`Encoder.Kind` `.utf32`, `Utf32Endian`, `Bom.utf32le/.utf32be` via the new `sniffBom32`
  and `decode32`; `sniffBom`/`decode` unchanged); `Encoding.x_user_defined` (**behavioural:**
  `lookupLabel("x-user-defined")` now returns `.encoding = .x_user_defined` and `LabelTarget.x_user_defined`
  is removed); DOS pages `Encoding.cp437/cp850/cp852` (IANA names and labels, vendored Unicode.org
  `CP*.TXT`, NOTICE extended); `utf8ValidUpTo`, `isAscii`, `asciiValidUpTo`, `latin1ToUtf8`,
  `utf8ToLatin1Lossy`; public `Custom(decode_table)` with `decodeCustom`/`encodeCustom`.

- **2026-10-20** — S2 batch and speed. Every WHATWG single-byte encoding (24 new `Encoding` tags,
  appended; tables generated from vendored WHATWG indexes by `tools/gen_tables.py`), the full WHATWG
  label table (`lookupLabel`, `LabelTarget`, `decodeReplacement`), `whatwgName` and introspection,
  caller-buffer `Decoder.decodeInto` / `Encoder.encodeInto` (`Progress`), the streaming `Encoder`
  (pages and UTF-16), unmappable modes (`encodeFromUtf8Opts`: `?`, ignore, `&#NNNN;`, fatal).
  **Behavioural:** a page byte the Standard leaves undefined decodes to U+FFFD (none of the five old
  pages has one), and `decodeFatal` refuses it. New core (`core.zig`): ASCII 32 bytes at a time,
  two-level reverse tables (the encoder searched 128 entries per character), Keiser–Lemire vector
  UTF-8 validation (`utf8_simd.zig`, simdjson port), branchless UTF-16 → UTF-8. Bench vs encoding_rs
  0.36–1.06× (was up to 40×).
- **2026-10-20** — **NO CONSUMER-VISIBLE CHANGE:** comparative bench `zig build bench-encoding` vs encoding_rs 0.8.42 and Go x/text v0.42.0 (tools only).
- **2026-10-18** — Ported to Zig 0.17.0: tests: enum iteration via `field_values`; `strRepeat` branch quota scaled with length.
- **2026-10-09** — tests: deterministic fuzz driver `ENCODING_FUZZ` over the existing harnesses.
- **2026-10-05** — **Behaviour change:** the labels `cp819` and `ibm819` (IANA's own aliases of
  ISO_8859-1:1987) now select `.iso_8859_1` with the rest of the iso-8859-1 family; they alone selected
  `.windows_1252` (the WHATWG mapping the module departs from for that family). Found by a golang.org/x/text
  differential oracle (`tools/go_oracle/`, replayed by `src/go_oracle.zig`): the WHATWG label table via
  htmlindex, and per-page encodability via charmap over U+0080..U+10FFFF. Anchor grade MIXED → EXTERNAL.

- **2026-10-04** — **mvp → core.** UTF-16 (`decodeUtf16`, `encodeUtf16`, `Utf16Endian`), BOM
  sniffing (`sniffBom`, `Bom`, `decode` = WHATWG "decode": a BOM overrides the fallback and is
  removed), a streaming `Decoder` (chunks of any size, split sequences carried over) and fatal
  mode (`decodeFatal`, `Decoder.Options.fatal` → `error.Malformed`). UTF-16 is deliberately not an
  `Encoding` member (every `Encoding` stays ASCII-compatible). **Behaviour change:**
  `decodeToUtf8(.utf8)` now replaces each maximal subpart of ill-formed UTF-8 with one U+FFFD, as
  WHATWG does (`e2 82` → one U+FFFD; was two). Checked against CPython's codecs on 5 669 cases
  (`tools/codec-oracle.py`), every split point; mutation 18 mutants, 0 surviving (1 equivalent).

- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/normative_test.zig`, `src/normative_vectors.zig` and `src/root.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-09-09** — Licensing correction, no code change. Two defects in `NOTICE`. First,
  it said the vendored tables "add no condition beyond MIT's own"; neither source is MIT,
  and CC-BY 4.0 §3(a)(1)(B) — indicate whether the material was modified — has no MIT
  counterpart. It is now discharged: the four `index-*.txt` files are byte-for-byte
  unmodified, and the file says so. Second, and worse, the Unicode License v3 permission
  notice was quoted with FOUR ellipses cut into it, while the clause being abridged is
  the one requiring "this copyright and permission notice appear with all copies". It is
  now reproduced verbatim and in full from https://www.unicode.org/license.txt.
- **2026-09-07** — **`fuzzCodecNeverLeaks` ran one input for ever: the empty
  string through `.utf8`.** It opened with `smith.bytes(&buf)` followed by
  `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes` consumes
  `min(buf.len, in.len)` octets and the ranged draw then reads eight *more* as a
  little-endian u64, returning the range minimum when fewer remain — so the drawn
  length was 0 for every input a seed can carry. Worse, `enc` was drawn AFTER the
  bytes, from an input the byte draw had already exhausted, so `smith.index`
  returned 0 on every run: **the encoding selected was always `.utf8`, the
  passthrough, and none of the five table-driven code pages was ever exercised by
  this target.** With no corpus either, the whole harness was a single cell of a
  6 × N matrix, and the emptiest one. Now one `smith.slice(&buf)` draw plus an
  explicit sweep over all six encodings, and a 12-seed corpus: the 0x80..0xBF band
  where the tables disagree, the eight positions separating iso-8859-15 from -1,
  Czech windows-1250 text, and the malformed-UTF-8 edges the audit found (a bare
  lead byte at the end of the buffer, a lead with too few continuations, a lone
  continuation, a UTF-8-encoded surrogate). The guard pins octets produced rather
  than acceptance, because neither codec ever errors: measured 0 / 0 / 0 before;
  208 UTF-8-decoded, 879 table-decoded and 550 table-encoded octets after.
- **2026-09-02** — Drift re-audit (window `7a9317f..HEAD`, +1334/-11 over 13 files, the first
  re-audit at Opus tier). The table-driven layer that landed since is **genuine**: all five
  vendored normative files are byte-identical to upstream fetched today, and the module agrees
  with both `iconv` (glibc) and python3 `codecs` on every one of 1280 decode and 43520 encode
  cases bar 10 slots where the WHATWG index files disagree with Microsoft/glibc on purpose — and
  the module follows the standard it names. "Never traps" survives re-testing across ~17M
  exhaustive inputs in both Debug and ReleaseFast. Four findings:

  - **MEDIUM, `decodeToUtf8` did not produce UTF-8 on its most-taken path.** For `.utf8` — the
    enum's first member, what `Encoding.parse` yields for an absent or unknown declaration, and
    what the README calls the default — it was a verbatim dupe, so a lone `0xFF`, a truncated
    `e2 82`, a surrogate and an overlong all came back unchanged from a function whose name is a
    promise, and a downstream `Utf8View` or JSON emitter met them believing otherwise. Malformed
    input is now replaced with U+FFFD, which is what the WHATWG decode algorithm does, so the
    guarantee is unconditional. Well-formed input is untouched.

  - **MEDIUM, the malformed-continuation resync had no test.** The `catch` arm that advances one
    byte is what makes "structural bytes survive transcoding" true; its two sibling arms were
    pinned and it was not, so changing `i += 1` to `i += seq_len` — which makes `e2 22 2c` lose
    both the quote and the comma, i.e. field-boundary desync — left the suite green. Code
    unchanged; the vector was missing.

  - **LOW, the label map rejected 23 of the 35 WHATWG labels** that select these five pages
    (`iso88592`, `l2`, `iso885915`, `l9`, `x-cp1250`, `csisolatin1`, …), so a caller fell back to
    its default on labels that occur in the wild, and it did not strip whitespace, so a label read
    off a CRLF header line kept its `\r` and matched nothing. Both fixed. The one **deliberate**
    departure — `iso-8859-1`/`latin1` select the true ISO-8859-1 page here, windows-1252 in every
    browser — is now stated in README, SPEC and the doc comment, and pinned by a test that shows
    the measured difference rather than left to be discovered.

  - **LOW, the vendored files carry a `# Identifier: <sha256>` of their own contents and nothing
    read it.** The anchor said "we vendored this once" rather than "this is still upstream's
    data". `parseWhatwgIndex` now returns it and `identifierMatches` reproduces upstream's hash
    from the parsed table; the four WHATWG files are checked against their own line.

  Doc corrections: "raw byte offsets stay valid" (README, SPEC, module doc) is false as written
  for decode — 4 MiB of `0x80` as windows-1250 is 12 MiB, exactly 3x; what holds is that a framer
  on the RAW bytes still finds its delimiters. And the 2026-08-14 fuzz entry's "arbitrary bytes
  already reach every branch" was wrong: the unmappable-codepoint fallback is provably unreachable
  for all five pages.


- **2026-08-14** — `zig build check-fuzz` coverage: a `testing.fuzz` harness on
  `decodeToUtf8`/`encodeFromUtf8` (the read-edge decode and write-edge encode entry
  points), run under `std.testing.allocator` with the result freed on every path. Both
  are data-lenient (never error on malformed input) so no structural bias was needed —
  arbitrary bytes already reach every branch. No panic, hang or leak found.
  ⚠ **"every branch" was wrong** (re-audit 2026-09-02): `decodeToUtf8`'s unmappable-codepoint
  fallback is unreachable for all five pages — every high byte maps, which `normative_test.zig`
  proves in the same repo — and `encodeFromUtf8`'s malformed-continuation arm was reached but
  held by nothing. The no-panic/no-leak result stands; the coverage claim did not.
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: The five supported
  code pages (windows-1250/1252, iso-8859-1/2/15) are the WHATWG Encoding Standard's
  published single-byte tables.
- **2026-07-09** — New module: Legacy single-byte code page ↔ UTF-8 transcoding (5
  European code pages: windows-125x, ISO-8859-1/2/15).
