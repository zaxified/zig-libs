# fleetsim — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `tcp.Error` gained a `Canceled` variant, and both raw-`poll(2)` waits in
  `tcp.zig` — `readable` (behind `serveTcp`'s accept budget and `serveTcpOn`'s idle-read
  wait) and `serveTcpMulti`'s many-descriptor readiness loop — now recover a `std.Io`
  cancellation instead of letting it disappear into an ordinary idle round. `std.posix.poll`
  retries on `EINTR` and a thread parked in it is never signalled by `Threaded` at all, so a
  canceled wait used to run to its full timeout and come back exactly like "nothing ready
  yet", leaving a caller that canceled a session (e.g. on shutdown) polling a peer or
  listener it had already abandoned. Both call shapes now call the new local
  `checkCanceled` once the wait ends, on the timed-out path and the poll-failed path alike,
  and surface `error.Canceled`. Two tests cover it (the single-peer idle-read wait, and the
  multi-peer readiness wait); both were confirmed to fail — the mutated build returned a
  normal success `Report`/`error.NoPeer` instead of `error.Canceled` — with the recovery
  reverted.

  A follow-up pass found `serveUdp` had the *inverse* problem: unlike the stream
  transports, `std.Io.net.Socket.ReceiveTimeoutError`/`SendError` already carry
  `Io.Cancelable` intact, so nothing needed recovering — but `serveUdp`'s `catch |e|
  switch (e) { error.Timeout => ..., else => break }` and `flushUdp`'s `socket.send(...)
  catch return any` both threw the variant away anyway, folding a canceled receive or send
  into an ordinary end-of-session `Report`. Both now have an explicit
  `error.Canceled => return error.Canceled` arm; `error.Timeout` ("nothing this round") is
  unchanged. A new test proves the receive-side fix (mutated: `expected error.Canceled,
  found` a normal `Report` after ~100 ms — a genuine `std.Io` call, so the cancel lands
  immediately rather than costing a full timeout; restored: green). The send-side fix has
  no dedicated test: reliably parking a thread inside a blocking UDP `send` long enough for
  a cancel to land needs a full kernel send buffer, which isn't a reproducible setup here —
  it was made by inspection and symmetry with the receive side instead. A full sweep of
  `tcp.zig` found no further arm of this shape (a directly-carried `Io.Cancelable` being
  discarded); the TCP data-transfer calls (`readVec`/`writeAll` in `serveTcpOn`,
  `serveTcpMulti`, `flush`, `flushMulti`, `writeTo`) have a *related but different* gap —
  `std.Io.Reader`/`Writer.Error` cannot carry `Canceled` at all, so recovering it there
  needs the out-of-band `reader.err`/`writer.err` inspection pattern used elsewhere in this
  collection (`enip`, `ssh`), not the direct-propagation fix applied here — and was left
  alone as a separate, unassigned piece of work.
- **2026-08-11** — Security audit: seven findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on ModbusPal / Kepware simulator
  (design ref); composes `netsim` + 7 protocol responders (design reference, not a test
  anchor).
- **2026-07-23** — New module: In-process simulated device fleet — hosts many protocol
  responders (Modbus, DNP3, IEC 104, S7comm, BACnet, EtherNet/IP, OPC UA) as addressable
  nodes on one deterministic, time-injected scheduler.
