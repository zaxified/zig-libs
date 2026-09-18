# imap — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-18** — **NO CONSUMER-VISIBLE CHANGE:** `Decoder.charge` gains a
  test-only call counter (`void` outside a test build, so the increment
  compiles to nothing there). F7's regression guard was an opt-in
  ReleaseFast wall-clock bench (`IMAP_BENCH_F7=1`) the default gate never
  ran; it is now a counted test in every mode — `quoted()` and `run()` take a
  256 KiB buffered run in a handful of `charge` calls, where the old
  per-byte loop made one per byte. `IMAP_BENCH_F7` no longer exists.
- **2026-09-13** — **BEHAVIOURAL:** A1 findings F1, F5, F9 (UTF-7 half).
  F1: `Client.searchMessages` took any `* SEARCH`/`* ESEARCH` as its answer — the ESEARCH
  correlator was parsed and never compared. It now refuses, with the new
  `error.SearchResponseMismatch`, an ESEARCH naming another tag (RFC 4466 §2.6.2), a second
  result, a rev1 `* SEARCH` to a search with RETURN options, and a RETURN search that gets no
  ESEARCH (RFC 4731 §3.1: "MUST return a single ESEARCH"). An ESEARCH without a correlator goes
  to the unilateral observer instead of becoming the result.
  F5: `fetchMessages`/`searchMessages` parsed every line straight into the caller's allocator,
  so uncollected untagged traffic accumulated there (18 MB on the wire kept 21 MB) and skipped
  `readLine`'s per-line depth reset. Both now read through `readLine` and deep-copy only the
  results into `out_gpa`.
  F9 (UTF-7 half): documented, not changed — a decoded mailbox name may contain control
  characters, which RFC 9051 §5.1 does not forbid.

- **2026-09-11** — **NEW, not breaking:** A1 fix campaign, F6 -- `LIST`/`LSUB`/`STATUS`
  had no parser at all. `wire.expectMailbox` (the UTF-7 decoder + `INBOX` canonicaliser a
  mailbox NAME needs) had zero production callers; `client.zig` had no `list`/`lsub`/
  `status` method; `response.zig`'s own test said so directly ("LIST is not parsed yet").
  New `list.zig`: `parseMailboxList` (`* LIST`/`* LSUB`, RFC 9051 §7.3.1), `parseStatus`
  (`* STATUS`, §7.3.2, the eight attributes real servers send), `encodeList`/`encodeLsub`/
  `encodeStatus` on the way out. Three new `response.Data` variants (`list`, `lsub`,
  `mailbox_status`) and three new `Client` methods (`listMailboxes`, `lsubMailboxes`,
  `statusMailbox`), built on the same `out_gpa`-collecting pattern as `fetchMessages`/
  `searchMessages`. Not a port -- these three commands are not in `emersion/go-imap`'s
  ported surface (`NOTICE`), so the shape follows this module's own encode/parse split.
  An unknown `mbox-list-extended` item or `status-att` extension is discarded, not
  rejected, matching the tolerance `readCode` already gives an unknown `[CODE]`.
  `scripts/modtest imap`: 153/154 (was 146/147), Debug and ReleaseFast.

- **2026-09-10** — **BEHAVIOURAL, not breaking:** A1 fix campaign, F9 (partial: the
  `FETCH BODY[...]` section half). `fetch.isSectionChar` was `ch != ']'`, so
  `BODY[A\r\nB]`/`BODY[A\x00B]` parsed and handed the caller a section string with an
  embedded CR/LF/NUL — a value the module's own encoder (`command.checkSection`) has never
  been able to build. Narrowed to mirror the encoder exactly: `ch != ']' and ch >= 0x20 and
  ch < 0x7f`. A response whose section contains a control byte or non-ASCII now fails with
  `error.UnexpectedByte` (the run stops at the disallowed byte, then the following
  `d.expect(']')` finds it instead) rather than silently handing the caller a poisoned
  section string. New test with the audit's own repro strings plus a positive control
  (`HEADER.FIELDS (FROM TO)` still parses). The other half of F9 — a modified-UTF-7 shift
  run decoding to a control character (`&AA0ACg-` → a bare CRLF) — is NOT closed this
  session: the obvious fix (reject control-class scalars out of a shift run) contradicts a
  cited upstream `go-imap` test table (`&AB8-`/`&AH8-`, U+001F/DEL, are asserted ACCEPTED
  there as "tier 2 (go-imap table)" vectors) — closing it would diverge this module's
  decoder from the reference implementation it is ported from, which is a bigger call than
  "tighten an unowned input", so it is left open with a question instead of a silent
  unilateral fix.


  (default 32 MiB) bounds the SUM of literal payload sizes accepted on one response line —
  previously only each individual literal was capped, so many small literals could stack
  past it (measured: 1,000 x 64 KiB literals on one line, 73.7 MB, was accepted outright).
  `Client.hasCap` no longer has a silent 64-byte ceiling on capability names. `* ESEARCH`
  without a correlator (`COUNT 5`, `UID ALL 1:3`, or bare `* ESEARCH`), which the RFC 9051
  ABNF allows, is now parsed instead of failing with `UnexpectedByte`. A duplicate name in
  `* CAPABILITY` no longer leaks a copy per repeat. No public API shape changed.
- **2026-09-09** — Docs: `NOTICE`'s port inventory said "Ported so far:" and then listed ONE
  file. Seven carry a `Ported from emersion/go-imap` line in their own headers — `utf7`,
  `wire`, `command`, `response`, `client`, `fetch`, `search` — so the inventory was wrong by
  six, which is most of the module. The reproduced MIT text was complete the whole time, so
  nothing was legally owed that was not paid; what was wrong was the record of WHAT was
  taken, and a record that answers the reader's question with a falsehood is worse than one
  that is absent. No code changed.
- **2026-09-08** — Test-only, no production change: the scalar knobs the three fuzz
  harnesses draw after their byte frame were measured across their corpora for the first
  time. `command.fuzzBuilders` was the one with a hole — `quoted_utf8` came out **true on 5
  of 5 seeds** and `literal_plus` **true on 5 of 5**, so both were constants. A knob stuck
  on `true` is as dead as one stuck on `false`: the modified UTF-7 mailbox spelling (which
  is a different output, not a variation of one) and every path that only exists when
  LITERAL+ is off had never been fuzzed. Two seeds carrying the complementary bits bring
  both to 5 of 7, and the corpus guard now pins all five knobs (5, 5, 5, 3, 3) alongside
  the argument octets, which rise 480 -> 672. `fetch.fuzzEncode`'s six knobs and
  `search.fuzzEncode`'s four bools measured alive already (4, 4, 3, 3, 4, 4 and 4, 4, 3, 4)
  and are now pinned rather than left implicit. `search`'s third draw is not a bool but
  `Criteria.larger`, a `u32`, and the seed builder wrote 0 or 1 into every word: measured
  maximum **1** across the whole corpus, so `LARGER` never rendered more than one digit.
  `shapedSeedLarger` gives two seeds a real width, pinned at `maxInt(u32)`.

- **2026-09-07** — **All five fuzz harnesses now receive their input; none of
  them did before**, including the two that had already been fixed once for
  exactly this and the one that already carried a deliberately shaped corpus.
  - `utf7.fuzzDecode`, `fetch.fuzzEncode`, `search.fuzzEncode` and
    `command.fuzzBuilders` opened `smith.bytes(&raw)` and then cut their
    arguments with ranged draws. `bytes` takes `@min(raw.len, in.len)` octets,
    so each ranged draw found fewer than the eight it needs and returned the
    range MINIMUM — every argument was empty and the drawn octets sat unread.
  - `response.fuzzResponse` drew the length FIRST, which fixed the ordering
    (audit `imap` F8) and introduced a worse problem: a weighted draw reads
    eight octets as a little-endian u64 and falls back to `weights[0].min` —
    zero — unless that u64 lands inside a declared range, which a written seed
    never does. It now draws with `smith.sliceWeighted`, which keeps the same
    short-input weighting for `--fuzz` and reads a corpus entry's own length,
    so a real response frame arrives intact.
  ⭐ **`command.fuzzBuilders`'s corpus was deliberately shaped and was still
  nearly empty.** Its own comment said the little-endian u64s behind the 96
  shaped octets fed "each scalar draw", meaning the four `Options` bools and
  `select`'s — but the harness took FIVE `valueRangeAtMost` length draws first,
  and those consumed the first five u64s, each carrying 0 or 1. So `tag`,
  `user`, `pass`, `name` and `flag` were **at most one octet long**, every bool
  was shifted five slots from the value intended for it, and the shaped octets
  went unread. Measured over that corpus: **18 argument octets in total across
  all five seeds**, out of 480 shaped. It is 480 now, and the fields are cut
  from the drawn length so no length draw is left to eat the tail.
  ⭐ **A corpus of refusals only is a finding, not a result.** `fetch`'s corpus
  was first written with fixed-width fields padded to their 48-octet slots and
  scored **0 of 6 accepted** — because no padding of a sequence set is still a
  sequence set. Both `fetch` and `search` now split the drawn octets at NUL
  separators (never valid in a sequence set, a section or a flag) with an
  equal-parts fallback for a mutation-engine draw, so a corpus entry carries
  arguments at their natural sizes: 4 of 7 accepted in each.
  ⭐ The five corpus guards pin what the collapse was hiding. For `utf7` and
  `response` that is an accepted/parsed count (10 of 20 names decoded, 31
  responses read); for the three encoders it is the total ARGUMENT LENGTH, not
  an accepted count — every one of those builders accepts the empty string, so
  "accepted" would have read ~100% while every argument was empty, the same
  shape that let `bacnet/service` score 19 of 19.
- **2026-08-11** — Security audit: the write path had no CR/LF discipline, so a
  caller-supplied argument containing a CRLF could inject a second IMAP command into an
  authenticated session; fixed, along with missing STARTTLS handling and five further
  findings.
- **2026-07-31** — New module: IMAP4rev2 (RFC 9051) client — complete: the
  modified-UTF-7 mailbox-name codec (RFC 3501 §5.1.3, canonical in both directions) and
  the §9 wire grammar decode side.
