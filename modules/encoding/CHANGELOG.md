# encoding — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
