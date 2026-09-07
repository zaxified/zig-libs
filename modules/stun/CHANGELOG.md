# stun — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — `fuzzDecode` had never decoded a message. It drew its packet with
  `smith.bytes(&packet)` and then took a length from `smith.valueRangeAtMost(u16, 0, 1024)`;
  a ranged `Smith` draw reads eight octets as a little-endian `u64` and returns the range
  MINIMUM when fewer remain, and `bytes` had already consumed them — so `len` was 0 on every
  input, `decode` returned `error.Truncated` at once, and the accessors, both verifiers and
  the attribute walk the test's own name promises were never executed. Now one
  `smith.slice(&packet)` call, plus a ten-message corpus (the three RFC 5769 vectors, the
  bad-cookie / non-STUN / two truncation refusals, a bare header, an ERROR-CODE response
  and an attribute whose length runs past the message) and a corpus guard pinning reach:
  **0 of 10 seeds non-empty, 0 decoded, 0 attributes walked before; 10 of 10 non-empty, 6
  decoded, 15 attributes walked and 3 messages MI+FINGERPRINT-verified after.** Documented
  in the harness: the `length near u16 max` overflow regression needs a 65 552-octet
  message and is out of reach of any stack-sized harness buffer by construction.
- **2026-08-18** — **BREAKING:** `query` gained a required `options: QueryOptions` parameter with a
  `timeout_ms` field (mirrors `sntp.QueryOptions`) so a caller can bound the wait for a reply instead
  of blocking indefinitely against a dark/unresponsive server; on expiry it returns `error.Timeout`.
  The default (`timeout_ms = 0`) preserves `query`'s original unbounded-wait behavior — this is a
  source-compatibility break (a fifth argument), not a behavioral one, for any existing caller.
- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).
