# iec104 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-02** — Drift re-audit (W2, window `d163578..HEAD`). Nine findings, seven fixed:

  - **HIGH, remote stall:** `TcpTransport`'s read timeout bounded only the fully-idle case. It
    polled once — and `poll` returns as soon as **one** octet is readable — after which both
    `readSliceAll`s blocked in the kernel with no deadline at all. A peer that sends one byte, or
    a complete and legal `68 FD` header promising 253 more, parked the read **forever**, and with
    it every t1/t2/t3 timer, because `poll` calls `transport.read` synchronously and `conn.tick`
    never runs again. Cost to the attacker: one connection and one octet; measured still parked at
    10× the configured timeout. The budget is now carried through the whole frame.
    ⚠ Both cancellation tests added in this window use a peer that sends **nothing**, so the
    fixture could not express the hostile input and the timeout was only ever exercised on the one
    path where it worked. ⚠ And `readSliceShort` is short *only at end of stream* — it loops until
    the buffer is full — so the first fix attempt reintroduced the block; it takes `readVec`.
  - **MEDIUM/HIGH, actuation ordering:** the outstation wrote `p.element` — i.e. fired the output
    — and only then built the activation confirmation, which can fail on a full reply sink. The
    breaker had moved, the master was told nothing, and the error then tore the connection down so
    it was never told later either: the HMI keeps showing the pre-command state while the field
    device has moved. The confirmation is now reserved before the output fires.
  - **MEDIUM, remote DoS:** with SQ = 1 the information-object addresses are **synthesised**
    (`base + i`), not read off the wire, and nothing bounded them. A base at the ceiling produced
    addresses this module's own encoder refuses with `AddressOutOfRange`, on the reply path of
    essentially every request type — so one legal 17-octet APDU dropped the connection. Refused at
    decode time now: a frame the decoder accepts must be one the encoder can echo.
  - **MEDIUM, guard disarmed by configuration `init` accepted:** a station configured with the
    reserved all-ones common address silently disabled the **entire** §7.2.4 broadcast guard
    (`isBroadcast` ends in `and self.opts.common_address != bc`), re-opening "stop broadcasting
    actuation" in full — the exact octets the regression test proves are dropped operated the
    point. ⚠ It was pinned as intended by a test whose fixture uses `C_IC_NA_1` only, so it could
    not see that the command case went with it. `init` refuses that address, and an address wider
    than the configured CA size, now.
  - **MEDIUM:** `frame_buf` at the documented minimum (`max_apdu_len`) could not survive ordinary
    TCP segmentation — a partial frame plus a full chunk overflowed it and `feed` returned
    `BufferTooSmall`, an error whose own doc comment said that could not happen. Both `poll`s cap
    the read at `capacity() - pending()`.
  - **LOW:** the reply queue was never compacted after a partial drain, so already-sent octets
    stayed dead space and the queue's effective capacity became "bytes queued since the last
    **complete** drain" — which no caller can size for, and which a master pipelining
    interrogations (legal) turns into `error.SinkFull` out of `poll`, i.e. a dropped connection
    rather than backpressure.
  - **LOW:** an I-format APDU with **no ASDU** was accepted; §5.1 gives it one by definition. It
    was caught downstream, but only after the state machine had counted the frame and advanced
    `recv_seq`. The S- and U-formats already rejected a body they did not expect.

  Recorded, not fixed: the wrap-replay golden test discards `tick`'s action and never compares the
  seven captured S-frames to anything, though the capture contains the w=8 ack cadence; and
  `fuzzHandle` ends in `catch return`, so it can only see a panic — it cannot see "a frame the
  decoder accepted made `handle` return an encoder-side error", which is what the SQ finding is.

- **2026-08-22** — `TcpTransport` now surfaces `error.Canceled` (a new
  `TransportError` variant) instead of `error.ReadFailed`/`error.WriteFailed`
  when a blocked read or write is interrupted by `std.Io`'s `Future.cancel`.
  Covers both the direct blocking read and the `read_timeout_ms` poll path,
  which is not itself a `std.Io` cancellation point and needed an explicit
  `checkCancel` after the wait to see the request at all.
- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against a
  live capture from `lib60870-C` (and its `c104` Python binding).
- **2026-07-23** — New module: IEC 60870-5-104 telecontrol — APCI/APDU framing, I/S/U
  formats with k/w flow control, ASDU codec for the common type IDs, and a
  transport-agnostic master (controlling station).
