# sntp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 audit fix campaign (`~/CML/20260901-zig-libs-audit/A1/sntp.md`), zero
  consumers in this repo, so hardening was ours to decide: `query`'s two anti-spoof guards (peer
  address/port match, origin-timestamp echo) held zero test coverage of their own — a mutation
  deleting either left the whole suite green (F1). Split them, plus a new truncation check, into
  `processReply`/`validateReply`, unit-tested directly without a socket; measured RED→GREEN by
  mutation, each guard caught on its own (F1, F2). A datagram longer than 48 bytes was silently
  accepted as if it were the plain packet this module parses, contradicting README/SPEC's own
  "longer packets are rejected" claim — the kernel truncates a UDP datagram to the buffer size on
  read and only a flag distinguishes it from a genuine 48-byte reply (F2). `decodeResponse` checked
  Transmit Timestamp for the RFC 4330 §5 all-zero sentinel but not Receive — a server reporting T2 =
  0 drove `query`'s offset to a measured -63 years with every other field honest (F3, new
  `error.ReceiveTimestampUnset`). The anti-spoof origin-timestamp nonce was `query`'s literal T1
  clock reading, measured at 21-24 bits of unpredictability against `verifyOriginate`'s claimed 64;
  `query` now sends the real second with 32 fresh bits from `std.Io.randomSecure` (fail-closed, new
  `error.EntropyUnavailable`) in place of the fraction, and uses the real clock reading — not the
  nonce — for the offset/delay math, so the swap costs no accuracy (F4). Leap Indicator 3
  ("unsynchronized") was accepted as a valid time source even though stratum's identical signal was
  already rejected — new `error.UnsynchronizedLeap`, closing the inconsistency (F7). `nowUnixNanos`
  silently returned the Unix epoch on a `clock_gettime` failure, with no signal to the caller;
  `nowUnixNanos`/`nowTimestamp` now fail closed with `error.ClockUnavailable` (F11, unreproduced on
  this host but a real fail-open default). Doc-only: SPEC.md claimed the peer-address/port and
  origin-timestamp checks were "out of scope" when `query` already implemented both (F8); the
  2036-tripwire test wasn't documented as a tripwire (F9); the "don't step a security-sensitive
  clock from one unauthenticated sample" caveat existed as half a sentence nowhere a caller would
  see it, now in README's own Security note (F12). `fuzzDecodeResponse`'s collapsing-draw bug (F5)
  and its own two audit findings were already fixed upstream (`8e468f69`, 2026-09-07) before this
  campaign reached the module. Deferred: the example's default-servers dialing real public NTP
  servers (F6) needs `check-examples`, a full-repo gate outside this campaign's per-module lane.
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
