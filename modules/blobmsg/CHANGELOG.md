# blobmsg — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **A1 fix campaign: 9 of 11 audit findings closed** (0 in-repo
  consumers, P1 — input hardening was free to tighten). `codec.zig`: a name/STRING
  must be NUL-terminated where declared and truncates at an embedded NUL instead of
  disagreeing with a C reader about the key/value (F3, F9abc); a TABLE field needs a
  name, an ARRAY element must not have one (F5, F9d); a blobmsg type id outside
  `BM.ARRAY..BM.DOUBLE` is rejected instead of decoding to JSON `null`, a shape this
  module's own encoder could not round-trip (F8); a NaN/Infinity DOUBLE now errors
  `error.InvalidValue` out of the JSON decoder instead of emitting `inf`/`-inf`
  (invalid JSON) or `"nan"` (valid JSON, wrong type) — F1; the INT8/16/32/64/DOUBLE
  exact-length guards gained oversized-payload tests closing the untested "too long"
  side (F6, mutation `!=`→`<` now caught). `root.zig`: `list`/`invoke`/`lookupId`/
  `subscribe`/`EventStream.poll` gained a `CallBudget` (1 MiB aggregate payload
  bytes + 2 s wall clock per call) — a daemon that never stops replying used to run
  unbounded, measured 96 062 933 B live from one LOOKUP that never closed (F2); a
  duplicate attr id within one reply now resolves to its LAST copy everywhere
  (matching upstream `blob_parse_attr`), closing the mismatch where `list()` and
  `invoke()`'s id resolution disagreed about which of two copies "the same" object
  meant (F4); mandatory-HELLO, stale-sequence-skip and too-short-OBJID guards
  (already correct, never tested) gained tests (F7). README/root.zig doc comment: a
  stale "byte-parity check has not been done" paragraph is now corrected — the real
  ubusd VM capture that answers it landed in commit `463e443e`, before this audit,
  and the paragraph was simply never updated (F11). Every closed finding has a
  measured RED (pre-fix)→GREEN (post-fix) run in
  `~/CML/20260901-zig-libs-audit/A1/blobmsg.md`'s disposition.
  **F10 (both fuzz harnesses running one empty input) was already fixed** by the
  2026-09-07 entry below, which postdates the audit — verified, not re-fixed. All
  11 findings are now closed.
- **2026-09-07** — **Both fuzz harnesses were replaying an EMPTY buffer, and the
  walker's buffer was too small for the module's own real captures.** Each opened
  with `smith.bytes(&raw)` followed by `smith.valueRangeAtMost(u16, 0, raw.len)`;
  `bytes` consumes `min(raw.len, in.len)` octets and the ranged draw then reads
  eight *more* as a little-endian u64, returning the range minimum when fewer
  remain — so the drawn length was 0 for every input a seed can carry. The
  `steps <= buf.len / 4 + 1` bounds in `fuzzCodec` had therefore never executed,
  and `fuzzEncodeArgs` was a complete no-op: `std.json.parseFromSlice("")` fails,
  so its `catch return` swallowed the only input it ever saw. ⛔ Separately, the
  walker's buffer was **512 octets while the module's largest frozen real ubusd
  reply body is 1988** (`captured_data_devstatus`; `captured_data_board` is 528
  and `captured_data_ifstatus` 780) — and a seed longer than the buffer reads back
  as the EMPTY one rather than a truncated one, so not one of the four real daemon
  replies captured from a live OpenWRT run could ever have passed through this
  module's own fuzz harness. Buffer raised to 2048; both harnesses now draw with
  one `smith.slice`. Corpora: 9 malformed attr images (every typed refusal the
  walker tests pin) plus three built by the module's own encoder and one real
  captured reply body; 12 JSON args covering every value kind, both root refusals
  and the 70-level `TooDeep` cap. Measured 0 attrs / 0 fields / 0 refusals and
  0 JSON parsed before; 10 / 5 / 7 and 9 parsed / 6 encoded / 196 octets after.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Wire format
  is clean-room from named OpenWRT sources and byte-parity-verified against `ubus -S`
  per README.
- **2026-07-05** — New module: OpenWRT ubus client + blob/blobmsg wire codec.
