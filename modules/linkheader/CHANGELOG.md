# linkheader — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — **mvp → core.** Every param of a parsed link: `Link.params()`
  (`ParamIterator`, borrowed, header order, repeats and unknown ones included),
  `Link.param(name)`, `Link.raw_params`; `anchor`, `media` and `title*`
  (`title_star`) as fields; `Link.extra` writes further params (preload's `as`,
  `crossorigin`, API-specific ones, `name*` ext-params). RFC 8187:
  `decodeExtValue`, `encodeExtValue`, `Link.preferredTitle` (decoded `title*`
  over `title`, RFC 8288 §3.4.1). `unquote` removes quoted-string escapes.
  `resolve` (RFC 3986 §5.2) makes a relative target or anchor absolute. RFC 8187
  §3.2.3, RFC 8288 §3.5 and all of RFC 3986 §5.4 are fixtures. Seeded
  corrupt-input sweep with pinned reach plus a build→parse oracle; mutation 41
  mutants, 0 surviving (1 equivalent, its branch removed).
  **Breaking:** `write` now returns `std.Io.Writer.Error || error{InvalidLink}`
  and `bufPrint` `error{ NoSpaceLeft, InvalidLink }` — the builder refuses (via
  the new `validate`, before writing any byte of that link) a URI with a control
  byte, SP, `<`, `>` or `"`, a quoted value with CR/LF/another control byte, a
  malformed or non-UTF-8 `*`-param, an empty `rel` and a non-token param name. It
  used to write them, so a CR LF in a title injected a header line and a `>` in a
  URI made the rest of it parse as params. An exhaustive `switch` on `bufPrint`'s
  error needs an `InvalidLink` arm.
  **Behaviour change:** a `media=` param now lands in `Link.media` (it was
  dropped); a parsed link carries `raw_params`.
- **2026-09-07** — **`fuzzParse` was replaying an EMPTY header, and now has a
  16-seed corpus with a measured reach guard.** It opened with `smith.bytes(&buf)`
  followed by `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes` consumes
  `min(buf.len, in.len)` octets and the ranged draw then reads eight *more* as a
  little-endian u64, returning the range minimum when fewer remain — so the drawn
  length was 0 for every input a seed can carry and `parse` was handed a zero-length
  slice while the header sat unread in `buf`. The target also had no corpus, so
  outside `--fuzz` it ran exactly one input for ever: the empty one. Now one
  `smith.slice(&buf)` draw, plus a corpus of the sixteen header shapes the value
  tests pin (quoted `,`/`;`, `\`-escaped quotes, unknown params carrying separators,
  an unterminated `<`). The guard pins links yielded rather than "did not crash",
  because `parse("")` is legal and yields nothing: measured 0 of 16 seeds non-empty
  and 0 links before, 16 seeds / 17 links / 7 titles after.
- **2026-07-19** — Security audit: no findings.
- **2026-07-08** — New module: Web Linking (RFC 8288) `Link` header build + parse
  (rel/title/type), `pagination` (first/prev/next/last), `find(rel)` — zero-alloc.
