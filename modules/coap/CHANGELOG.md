# coap — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit (last audited `e5594e8`; the codec's byte handling came back
  PASS then and still does — what changed is that the state machines and the resource surfaces got
  looked at). Six fixes, nine mutations, nine red.
  - **`observe.isNewer` implemented two of RFC 7641 §3.4's THREE freshness conditions.** The
    missing one, `T2 > T1 + 128 seconds`, is the recovery path — and without it the comparison
    WEDGES: a notification carrying `2^23 - 1` is "newer" than every value in `[0, 2^23)`, so it
    needs no knowledge of the current sequence, and one spoofed datagram makes every genuine
    notification that follows read as stale, permanently. `Registry.find` keys on `(token,
    resource)` and never on a source address, so on plain UDP that is one packet. Measured:
    1998 of 1998 genuine notifications rejected after a single injection. The benign version is
    just as real — a server restart resets `Sequence` to 0 and stays blind until it climbs back.
    The third condition was not merely unimplemented but **structurally unimplementable by a
    caller**: `Entry` had no timestamp, so nobody could have added it on top. `Entry.last_ms` and
    a `now_ms` argument on `register`/`tryRegister`/`notify` (source-breaking) now express it, with
    `isNewerAt` beside `isNewer`. The 128 s constant is the RFC's, and the test pins it as a
    literal — written as `t0 + reordering_window_ms + 1` the test scaled with the constant it was
    meant to guard and stayed green with the window widened to four years.
  - **`observe.decodeValue` accepted an over-long option value and kept its LAST three bytes.**
    Worse than truncating: the attacker chooses the outcome with padding — `{0,0,0,1}` decoded as
    `deregister` and `{1,0,0,0}` as `register`, the same four bytes in the other order, while a
    conformant peer rejects both. `coap.parse` puts no length limit on an option value, so this is
    straight off the wire. Now `error.OptionValueTooLong`, matching `Block.decode`'s `TooLong` and
    the `FormatError.OptionValueTooLong` that commit `4ba6317d` added to `contentFormat`/`accept`
    in this same window — with the reason already written in its source ("rejecting is safer than
    silently `@truncate`-ing an attacker-supplied over-long value to a plausible-looking
    identifier"). That argument had been applied to the two options it was found on, not to the
    rule; this is the third decoder.
  - **The CON backoff wrapped `u32` and collapsed to a ZERO-length window.** `max_retransmit` is a
    public `u8` documented as tunable; at the 2000 ms base the window leaves `u32` at retransmit
    #22 and reaches 0 by #28, after which `poll` answers `.retransmit` on every call — a
    self-inflicted packet storm exactly when the network is worst (and an integer-overflow panic in
    Debug). Now saturating. The suite's schedule test only ever ran the default 4.
  - **`Retransmit.init` died on an ACK_RANDOM_FACTOR below 1.** RFC 7252 §4.8 requires it above 1
    and nothing validates `Params`; both obvious spellings of "no jitter" (`0`, and `1` meaning
    1.0) underflowed `factor - 1000` on a `u32`. Debug panicked, ReleaseFast was UB — observed as
    both a SIGSEGV and a runaway, which is what UB looks like. Clamped to 1000, which IS "no
    jitter", keeping `init` infallible.
  - **Three checks in the client's correlation path had no teeth.** Deleting the piggybacked-ACK
    token check, or the Reset message-id check, or the `token_len` clamp each left all 73 tests
    green: the match test's two "unrelated" cases are a wrong-mid ACK and a wrong-token CON, so
    neither reaches a right-mid/wrong-token ACK or a wrong-mid RST. Tests added for both. The
    `token_len` clamp is now a **rejection** (`error.BadTokenLength`) — silently shrinking a token
    is the wrong direction on the field that carries this client's anti-spoofing entropy, and the
    clamp was also the only thing between a caller's `token_len = 16` and an out-of-bounds slice of
    an 8-byte array.
  - **The token is a counter, and that is now stated where a reader will meet it.** `Client`
    advances `next_mid` and `next_token` by one per request, so the token carries exactly the
    unpredictability of its seed. RFC 7252 §5.3.1 asks for "a nontrivial, randomized token" and
    §11.4 rests its whole anti-injection argument on an attacker having "to guess both the Message
    ID and the Token"; seeded with a constant, every later exchange's pair is arithmetic. Measured:
    five requests from `Client.init(0x1000, 0x40)` give tokens `00000040`..`00000044`, and a
    forged ACK built from the *predicted* pair alone matched as `.piggybacked` without the attacker
    ever seeing the real exchange. `RequestOptions.token_len` and `Client.init` now say this, and
    `example/main.zig` — which hard-coded both seeds and is what a consumer copies — draws them
    from `io.randomSecure`.
  - Two guards that had never been reached now have tests: the accumulated option number's u16
    bound (reachable in a 10-byte datagram; past it the `@intCast` truncates silently in
    ReleaseFast) and the block assembler's coverage monotonicity (a re-sent short block used to be
    able to shorten what was already assembled).
- **2026-09-03** — Docs: SPEC.md's threat model enumerated two attacker-triggerable UDP items and
  called them addressed, which reads as an enumeration of the UDP surface. It was not one. Added
  RFC 7252 §11.3 response amplification and RFC 7641 §7's Observe notification MUST, both marked
  **not bounded by this module**. Also corrected the anchor's framing: "two independent real
  endpoints" is two endpoints of ONE implementation (`aiocoap-client` + `aiocoap.resource.Site`),
  no golden exercises a refusal path, and the "full capture recipe" SPEC.md pointed at is a
  narrative with no command in it — so the goldens cannot currently be re-taken. Recorded, not
  fixed. The §3.4 reordering rule was also cited throughout as §4.4.
- **2026-09-03** — ⛔ **Recorded, NOT fixed.** RFC 7641 §7's notification-volume MUST: `Registry`'s
  `admit_fn` and `max_per_source` both bound table SLOTS, and a registration's cost is the
  notification stream that follows it, unbounded in time. `Entry` has no unacked-notification
  counter and no last-ACK timestamp, so a caller cannot implement the MUST on this API either. The
  fix is a per-entry budget plus a CON-interspersal point in the push path, changing `Entry` and
  the caller's loop together. Separately, `test "fuzz: parse never panics on arbitrary bytes"` runs
  as a single degenerate iteration under `zig build test-coap` — the command SPEC.md names as this
  module's verification — so a `@panic` planted inside `parse` at a TKL reachable by ~6% of random
  4-byte datagrams survives all 73 tests; and the harness covers `parse` only, while
  `block.Block.decode`, `observe.decodeValue`, `options.decodeUint` and `options.optionsFromUri`
  have none. `zig build --fuzz` does not compile on this toolchain at all, which is why every new
  oracle in this repo runs only in the deterministic lane.

- **2026-07-19** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against RFC 7252.
- **2026-07-08** — New module: CoAP (RFC 7252) — a full client/server stack: message
  codec (header/token/delta-encoded options/payload), `options` (registry, CoAP uint,
  URI ↔ options §6), `reliability`.
