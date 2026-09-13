# websocket — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-14** — **BREAKING (error set):** A1 F6, round-2 decision Q7 (API change allowed, consumer
  fixed in the same batch). `writeFrame` guarded the control-frame invariants (`fin`, payload ≤ 125)
  with `std.debug.assert`: in ReleaseFast a 200-byte ping went out as `89 7e 00 c8`, which this
  module's own parser rejects, and in Debug/ReleaseSafe the same call panicked the process — while
  `pongFor` builds `WriteOptions` from a received payload. `writeFrame` now returns the new
  `frame.WriteError` (`std.Io.Writer.Error || error{FragmentedControlFrame, ControlFrameTooLarge}`)
  and refuses such a frame before writing a byte. Consumer `bacnet` (`sc_ws.writeMessage`, always
  one binary frame) keeps its signature and maps the two new variants to `unreachable`.

- **2026-09-11** — A1 fix campaign, F5's second half (test-only, no
  production behavior change): `connection.zig` and `handshake.zig` had zero
  fuzz harnesses, and the `.client` role had none anywhere in the module, so
  `error.MaskedServerFrame` (the one rule that only exists for that role)
  was never exercised by anything adversarial. Three new fuzz targets, each
  with a paired `corpus: ...` reach test that replays the same corpus
  deterministically (no `--fuzz` needed) and pins how many seeds produce
  each class of outcome -- the discipline this campaign's `opaque` module
  needed and didn't have, where three harnesses never got past `fromBytes`
  and so could never have found anything:
  - `Connection.receive`, `.client` role: fragment reassembly across two
    frames, the close handshake, `MessageTooLarge` mid-reassembly,
    `TooManyFragments`, `DataAfterClose`, and -- the named gap --
    `MaskedServerFrame` (a masked frame is illegal from a server).
  - `handshake.verifyResponse`, `.client` role: fuzzes
    `h1.ResponseHead.parse` and `verifyResponse` together (the real
    attacker-controlled input is the raw bytes, not the pre-parsed head),
    covering every one of its seven error variants including
    `AcceptMismatch`, the core anti-cache-poisoning check.
  - `handshake.acceptHandshake`, `.server` role: same shape, the other
    direction, covering all eight of its error variants.

  scripts/modtest websocket: 85/85 (Debug and ReleaseFast); consumer
  `bacnet` unaffected (257/260, 3 pre-existing environment-gated skips).

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `verifyResponse` now rejects a `101` response
  that carries a `Sec-WebSocket-Extensions` header (`error.UnexpectedExtension` — this module
  never offers an extension, so any value there is unrequested per RFC 6455 §4.1 point 5) or a
  duplicated `Upgrade`/`Sec-WebSocket-Accept`/`Sec-WebSocket-Protocol` header
  (`error.DuplicateHeader`, mirroring the server side). `acceptHandshake` now also rejects a
  duplicated `Sec-WebSocket-Protocol`. `writeRequest` now validates `host`/`target`/`key`/
  `protocols`/`extra_headers` for CR/LF/NUL injection before writing anything
  (`error.InvalidRequestField` — new member on `writeRequest`'s return type, additive). A caller
  passing well-formed fields (the only kind a conforming implementation sends) sees no change.
  `connection.Connection` gained `max_fragments` (default 65536, new field with a default) —
  `error.TooManyFragments` once a single reassembled message exceeds it — and any error from
  `receive` now resets in-progress fragmentation state instead of leaving it for a later,
  unrelated frame to splice onto.
- **2026-09-07** — Fuzz reach: both `frame.zig` harnesses ran on an empty input, and one of
  them never called the parser at all. Each opened with `smith.bytes(&buf)` followed by a
  ranged length draw; a ranged draw reads eight octets as a little-endian u64 and returns the
  range MINIMUM when fewer than eight remain, and `bytes` had already eaten the seed, so `len`
  was **0 on every input**. In `fuzzParseFrameServer` that `len` is the bound of the
  parse-and-advance loop, so `parseFrame` was **never invoked** — while the comment above it
  promised multi-frame streams and `.need_more` retries. In `fuzzDecodeCloseBody` the collapse
  looked healthy instead: `decodeCloseBody("")` succeeds by design (§5.5.1), so the harness
  returned a `CloseInfo` on all 19 rounds without ever reading a close code. Both now draw with
  one `smith.slice(&buf)` and carry a commented corpus with a guard pinning measured numbers.
  Measured 2026-09-07, before → after: `fuzzParseFrameServer` 0/18 seeds reaching `parseFrame`
  and 0 frames parsed → 18/18 and 7; `fuzzDecodeCloseBody` 19/19 "accepted" with 0 close codes
  read → 11 accepted, 10 codes and 131 reason octets validated.

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  6455 §5.7's published test vectors.
- **2026-07-22** — New module: RFC 6455 WebSocket — opening handshake + frame layer
  (masking direction enforced, fragmentation, control frames, UTF-8 validation, close
  codes, per-frame + aggregate size caps), transport-agnostic.
