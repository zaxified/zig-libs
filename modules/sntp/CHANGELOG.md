# sntp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — `fuzzDecodeResponse` was decoding nothing. It drew its bytes with
  `smith.bytes(&buf)` and then took a length from `smith.valueRangeAtMost(u8, 0, 64)`; a
  ranged `Smith` draw reads eight octets as a little-endian `u64` and returns the range
  MINIMUM when fewer remain, and `bytes` had already eaten them — so `len` was 0 on every
  input and `decodeResponse` was called with an empty slice, failing at `error.InvalidLength`
  before reading a single field, with the datagram sitting unread in `buf`. Now one
  `smith.slice(&buf)` call, plus an eleven-datagram corpus (the captured pool reply, the
  canned reply, and the length/mode/version/stratum/transmit/Kiss-o'-Death refusals) and a
  corpus guard that pins reach and outcome: **0 of 11 seeds non-empty, 0 accepted and 11
  identical `InvalidLength` before; 11 of 11 non-empty, 3 accepted, 2 `InvalidLength` and 2
  `KissOfDeath` after.**
- **2026-08-22** — Competitive-survey gaps: `decodeResponse` (and `query`) now take an optional
  `kiss_out: ?*KissOfDeath` and surface the parsed RFC 5905 §7.4 `KissCode` + raw reason bytes on
  `error.KissOfDeath` instead of discarding them; stratum ≥ 16 ("unsynchronized"/reserved, RFC
  5905 §7.3) is now rejected as `error.UnsynchronizedStratum`. Sweep of `decodeResponse` per RFC
  4330 §5 sanity check 4 (as corrected by verified RFC Errata 2263, which reassigns the check from
  LI to VN) turned up two more unchecked fields, both fixed: version 0 (`error.InvalidVersion`) and
  an all-zero Transmit Timestamp (`error.TransmitTimestampUnset`). The NTP era-0 (2036-02-07)
  timestamp bound is a known, documented limitation — not fixed, matching upstream `sntpc`'s own
  unresolved gap.
- **2026-07-19** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against RFC 4330.
- **2026-07-09** — New module: SNTP client (RFC 4330) — NTP packet codec + UDP query,
  clock offset / round-trip delay.
