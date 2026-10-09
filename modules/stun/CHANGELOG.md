# stun — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — tests: deterministic fuzz driver `STUN_FUZZ` over the existing harnesses.

- **2026-10-09** — **BREAKING:** `longTermKey(out: *[16]u8, username, realm, password) void` writes the key into `out` (was: returned `[16]u8` by value, leaving a copy in the caller's frame); migrate with `var key: [16]u8 = undefined; longTermKey(&key, ...)` and wipe `key` after use. `longTermKey` (8 KiB), `Builder.addMessageIntegrity` and `Message.verifyMessageIntegrity` (2 KiB, per packet) now run under dead-stack burns (`burn.zig`); new `stackprobe_test.zig` on `testkit.stackprobe`.

- **2026-10-04** — mvp → core (survey 2026-09-30 backlog). ADDED: the server side
  (`bindingResponse`, `ResponderOptions`, `RespondError`) — reproduces RFC 5769 §2.2/§2.3 byte
  for byte; `longTermKey` (RFC 8489 §9.2 MD5 key; verifies RFC 5769 §2.4); `parseUri`
  (RFC 7064/7065 stun/stuns/turn/turns); `Builder.addErrorCode`/`addUnknownAttributes`/
  `addUsername`/`addRealm`/`addNonce` and `Builder.pad`; `Schedule`; `AttributeType` gained
  MESSAGE-INTEGRITY-SHA256 / PASSWORD-ALGORITHM / USERHASH codes; `BuildError` gained
  `ValueTooLong`/`InvalidErrorCode`. BEHAVIOURAL: `query` now retransmits per RFC 8489 §6.2.1
  (defaults: RTO 500 ms doubling, 7 requests, give up 39.5 s after the first — so
  `timeout_ms = 0` no longer waits forever); `max_requests = 1` restores a single send. A reply
  with another transaction id (or a non-STUN datagram) is discarded instead of failing at once;
  it is reported only if nothing better arrives before give-up. An error response now returns
  `error.ErrorResponse`. Every error name `query` could return before is still in its set, so
  existing `switch`es compile (axp's included); with axp's `timeout_ms = 2000` a lost request is
  now resent at 500 and 1500 ms. Self-review: the schedule saturates instead of overflowing at
  `max_requests = 255` (test added). Mutation: 31 mutants, all killed (1 after a new test).

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
