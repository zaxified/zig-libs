# linkheader — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
