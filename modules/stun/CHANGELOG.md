# stun — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-03** — **BEHAVIOURAL, not breaking** (`looksLikeStun`; review round). ADDED, no existing signature or error set changed: `Message.addressCovered`, `mappedAddressCovered`, `uint32Covered` (an on-path attacker can append OTHER-ADDRESS & co. behind the MAC and the MAC still verifies; the plain accessors see them, the covered ones do not; README says which to use). `bindingResponse` takes `ResponderOptions.integrity_key_sha256` / `integrity_sha256_tag` (a bad tag length falls back to 32). `longTermKeySha256`, `userhash`, `Builder.addUserhash`, `Message.userhash`, `PasswordAlgorithm`, `Builder.addPasswordAlgorithm(s)`, `Message.passwordAlgorithm(s)`, `PasswordAlgorithmIterator`. BEHAVIOURAL: `looksLikeStun` now also requires the first byte < 4 and `20 + length == bytes.len` (RFC 7983, one datagram); it is two days old and unreleased. Tests: fuzz harnesses compare every accepted address with `address()` (XOR types and v6 included), reach per attribute type and a correct SHA-256 MAC; Python goldens for the 16-byte tag, USERHASH and the SHA-256 key; stack probe with a 100-byte key and a 16-byte tag (a mutant with `mi256_burn = 0` turns it red: dirty 1343 B); ctgrind `mi256` wired into `scripts/checks/ctgrind.sh` and pinned (stun pins re-taken, `mi`/`ltkey` output digests unchanged). Every previously "deferred" feature now has a verdict in SPEC.md.

- **2026-11-03** — parity survey against pion/stun v3.1.6 (survey 2026-11-02). ADDED (no existing signature or error set changed): `AttributeType` gained the RFC 5780 / RFC 8445 / RFC 8656 / RFC 8489 §18.3 codes; `Builder.addAddress`, `addUint32`, `addChangeRequest`, `addMessageIntegritySha256(key, tag_len)` (returns `BuildError || error{InvalidTagLength}`); `Message.address`, `otherAddress`, `responseOrigin`, `alternateServer`, `uint32`, `changeRequest`, `verifyMessageIntegritySha256`; `looksLikeStun`; `randomTransactionId(io)`. Fuzz: new `STUN_FUZZ_BUILD` driver over the mutating `Builder` API, the decode harness reaches the new accessors; sweep tests for the new inputs; stack probe and a ctgrind `mi256` target for the SHA-256 MAC (the ctgrind row is not wired in `scripts/checks/ctgrind.sh` yet). New `tools/bench.zig` + `tools/go_bench{,_gortc}` (`zig build bench-stun`): 0.47-0.55x pion on encode/decode, 0.004x on hostile rejects. ReleaseSmall size of a `stun.query` program unchanged (mips32-musl-soft-float, arm, x86_64).

- **2026-10-31** — no-panic sweep + blind review (§ GV). `Builder.addAttribute` checks the value length before narrowing it (65536 B trapped) and the attribute region against its u16 length field (`ValueTooLong`/`BufferTooSmall`); query deadline clamped. New `Message.findCovered` (RFC 8489 §14.5): attributes after MESSAGE-INTEGRITY other than FINGERPRINT are ignored — `bindingResponse` no longer counts a USERNAME the MAC does not cover. Worst-case total wait of `max_requests` with `timeout_ms = 0` documented.
- **2026-10-18** — Ported to Zig 0.17.0. enum `@typeInfo` loop uses `field_names`/`field_values`. Also: comptime `strRepeat` helper quota raised.
- **2026-10-09** — Constant time: new `src/ctgrind_harness.zig` (`scripts/checks/ctgrind.sh stun`, targets `mi`, `ltkey`). The MESSAGE-INTEGRITY key through `Builder.addMessageIntegrity` and `Message.verifyMessageIntegrity` (valid and tampered message), and the password through `longTermKey`, show 0 secret-dependent contexts in ReleaseFast. Pinned in `ctgrind-expected.tsv`. No code change.

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
