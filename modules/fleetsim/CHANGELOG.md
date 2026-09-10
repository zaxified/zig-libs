# fleetsim — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 fix campaign, oracle-audit follow-up (zero consumers,
  confirmed against `build.zig`'s `example_apps` table as well as
  `module-graph` — P1 applies without qualification). Four of the seven
  findings turned out to be **already fixed** by the `2026-09-01` security
  audit commit below, before this session started; verified against
  `114eb1fe9^` (RED) vs. today's tree (GREEN), `114eb1fe9` confirmed an
  ancestor of this branch. Two more get test-only fixes this session. One
  stays open, deliberately.

  - **F-A** (HIGH, OPC UA ACKF golden couldn't discriminate the handshake
    negotiation it claimed to anchor) — already fixed in `114eb1fe9`: the
    HELLO's four limits are asymmetric and straddle the server's ceilings,
    re-anchored against a fresh Wireshark 4.6.4 reading. Confirmed still
    fixed: both survivor mutations from the audit (drop the receive/send
    cross-swap; echo `max_message_size` verbatim) go RED on this test alone.
  - **F-B** (MED, S7comm Connect-Confirm golden couldn't discriminate the
    COTP reference placement) — already fixed in `114eb1fe9`: the CR's
    source reference is `0x0004` instead of `0x0001`, so destref/srcref
    placement is no longer symmetric; re-anchored against Wireshark.
  - **F-D** (MED, two concurrent `test-fleetsim` runs make one fail with a
    wrong verdict) — already fixed in `114eb1fe9`: the three hardcoded TCP
    ports (`15571`/`15572`/`15573`) now derive from the pid, strided by
    four. `114eb1fe9^` still has the literal ports.
  - **F-F** (LOW, EtherNet/IP Wireshark vector used an all-zero sender
    context) — already fixed in `114eb1fe9`: the RegisterSession request
    now carries `"zigfleet"` as the sender context instead of eight zero
    bytes, so an adapter that drops the echo is now visible to this vector
    too (previously mitigated only by the `master_goldens` pycomm3 corpus).
  - **F-C** (MED, the S7 negotiated-PDU mark (`db2[8]`) is a verbatim echo
    of the number the master itself proposed, because the live fixture's
    device ceiling equals the master's proposal) — **left OPEN.** The
    comment was already corrected in `114eb1fe9` to say plainly that the
    mark is an echo; the substantive fix (re-record the VM-lane session
    with the device ceiling set BELOW the master's proposal) needs the
    disposable-VM master lane, which this session does not have access to.
    ⏸ ODLOŽENO NA KONEC KAMPANĚ — vyžaduje VM lane / plnou bránu.
  - **F-E** (MED, `SlotLeak` is a correct fleet-internal conservation
    invariant with no positive control — no `Bug` arm on `BrokenDevice` can
    reach the in-flight pool) — **fixed.** Added `Fleet.leak_slot_once`, a
    test-only one-shot hook that silently drops the next slot instead of
    returning it (default `false`, additive field), and `Vopr.Options
    .leak_slot` to arm it on rebuild. New test
    `"vopr: SlotLeak fires when a slot is silently never returned"`.
    Measured: on `114eb1fe9` (pre-fix), neutering the `SlotLeak` predicate
    (`if (false and ...)`) leaves the whole suite green (89/89, 0 fail) —
    reproducing the audit's own "SURVIVED" finding exactly. On this fix,
    the same neutering now fails the new test alone (89 pass, 1 fail);
    reverted, clean tree is 90/90.
  - **F-G** (LOW, four guards in `vopr.zig` are correct but untested) —
    **partially fixed.** Items 3 and 4 get direct tests against `onReply`
    (no fleet or adversary needed — the oracle reads only bytes): a reply
    with `txid == 0` (item 4, the half of `UnknownTransaction` no existing
    `Bug` arm reaches) and a reply whose PDU byte count disagrees with the
    read size while staying frame-length-consistent (item 3 — until now
    `length_counts_retransmit` always tripped the FRAME-length check one
    guard up before this one was ever reached). Measured on the pre-fix
    tree: neutering both guards together leaves the suite green (89/89).
    On the fix: each neutered individually fails exactly its own new test
    (91 pass/1 fail each); the byte-count mutation additionally turned up a
    **real out-of-bounds panic** — without the guard, `onReply`'s value
    loop reads `read_count * 2` bytes starting at a fixed offset regardless
    of what the frame actually carries, so a short reply drives it past the
    buffer end (a genuine bounds-safety property, not merely a grading
    gap). Items 1 (the poll-timer generation guard) and 2 (the `pump` call
    at the top of `onTimer`) are left open — both need a working `netsim.Sim`
    (crash+restart timer races, tick-during-silence), out of proportion to
    a LOW-severity, direct-unit-test session. Item 5 needs no action; its
    own comment already states the guard is unreachable-by-design and that
    was re-verified.

  `scripts/modtest fleetsim`: 92/92 (8 skipped; Debug and ReleaseFast).

- **2026-09-07** — **Test-only: the six-adapter dispatch fuzz target built no
  fleet, added no node and submitted no frame — it returned before allocating
  anything, on every run it has ever made.** `fuzzSmith` drew
  `smith.bytes(&buf)` and then `smith.valueRangeAtMost(u16, 0, buf.len)`;
  `bytes` consumes `@min(buf.len, in.len)` octets, so the ranged draw found
  fewer than the eight it reads as a little-endian `u64` and returned the range
  MINIMUM. `len` was 0 for every input the ordinary test lane can carry, and
  `fuzzDispatch`'s first line is `if (input.len == 0) return;`. Measured
  2026-09-07: **1 input, 0 octets, 0 chunks, 0 submissions.** ⭐ The invariant
  the harness asserts — every in-flight slot back in the pool once the queue
  has drained — holds *trivially* when nothing was ever submitted, which is
  exactly how the target reported success while doing nothing. The seven inputs
  that already existed as a separate deterministic test the fuzz lane could not
  see are now the target's corpus too (grown to 11: a chunk head cycling
  through all six adapters, a length octet claiming more than remains, and a
  Modbus request behind a length octet so it arrives as one frame). Measured
  after: **11 of 11 seeds non-empty over 208 octets, 89 chunks cut and 89
  submitted.** `master_goldens.zig` is untouched — its bytes are a
  provenanced pymodbus recording and not a fuzz corpus.

- **2026-09-01** — Security audit.
  **One silent TCP connection wedged the whole `serveTcpMulti` loop.** `fds` is built from the
  peers active BEFORE the accept pass; the read loop walked the peers active AFTER it with a
  running cursor into `fds`. A peer accepted during that pass is active but has no entry, so
  from it onward every peer read someone else's `revents` — or, for the last one, an entry never
  written that round, which on the first round is the allocator's `0xaaaa` fill, whose bit 3 is
  `POLL.ERR`. The gate then opened and the loop entered a BLOCKING read on a peer that had sent
  nothing. Measured: `run_ms = 700`, actual **3120 ms** — released by the peer's disconnect, not
  by its own deadline, so a peer that connects, stays silent and never hangs up starves every
  other master on the single thread they share. Each peer now carries its own poll-set index;
  a peer with none has not been polled and is not treated as ready. `git blame` puts the cursor
  at `a2c2e79c` (2026-07-23), before both prior audits.
  **A canceled `serveTcpMulti` leaked one descriptor per connected master.** Peers were closed
  only on the normal exit path, and the cancellation campaign added early returns that skip it.
  Allocations were always fine — every `gpa.free` is a `defer` — so no allocator could see it.
  **A canceled `accept` was reported as `NoPeer`, and `serveTcp` turns that into success.**
  `AcceptError` ends in `Io.Cancelable`; `catch return error.NoPeer` threw it away, and with a
  session already connected the caller got a normal `Report` for a cancel it requested.
  `Threaded.checkCancel` reports `.canceling` once, so no later round recovered it either. Both
  accept sites now surface it. ⚠ `f5b05324`'s claim that "a full sweep found no further arm of
  this shape" was wrong: these two are the arms.
  **A `run_ms` above 2^31 ms panicked.** `poll(2)`'s timeout is signed and negative means
  forever, so the bare `@intCast` from these `u32` options crashed in Debug/ReleaseSafe and
  became an infinite wait in ReleaseFast — from an ordinary "run for a month" value. Saturates
  now.
  **Two concurrent `test-fleetsim` runs produced a false RED.** Three hardcoded ports meant the
  winner of the bind accepted the loser's clients too: `expected 2, found 1` / `found 3` /
  `found 4`, on an assertion that looks entirely real. It fired accidentally on three separate
  occasions during this audit, and `scripts/test.sh` runs modules in parallel. Ports are now
  derived from the pid, strided by four — a stride of one still failed, because processes
  spawned together get consecutive pids.
  **Anchors that recorded a property without discriminating it** (the F7 shape, three more
  occurrences, each re-anchored against a fresh Wireshark 4.6.4 reading rather than
  re-commented): the OPC UA ACKF vector proposed limits equal to the server's own, so
  `rbs == sbs` and `mms` was the client's own number echoed — dropping the receive/send
  cross-swap, and separately never applying the server's own ceiling, both left the suite green,
  and those four fields are `opcua`'s documented denial-of-service bounds. The S7comm Connect
  Confirm carried `destref == srcref`, so swapping the two assignments emitted a byte-identical
  frame. The EtherNet/IP RegisterSession used an all-zero sender context, so the echo was
  indistinguishable from dropping it. All three now go red under exactly those mutations.
  **A broken server was reported as an unavailable port.** The two round-trip tests skipped on
  `BindFailed, error.NoPeer` — but `NoPeer` is a SERVER verdict when the client threads did
  connect. Inverting `readable`'s readiness predicate, i.e. breaking the central readiness
  decision, made the test print "cannot bind" and count green. `NoPeer` is now a failure.
  **`FLEETSIM_EXPECT_TCP=1`**, the sibling of `FLEETSIM_EXPECT_LIVE` for this module's loopback
  tests: every test in `tcp.zig` gives up with `SkipZigTest` if a socket call fails, and a skip
  reports PASS, so the whole real-socket surface — the four cancellation guards included — could
  vanish into a green run. Set it where loopback is expected to work.
  **The example discarded its own leak verdict** (`defer _ = gpa_state.deinit()`), and it is the
  only leak check outside the test suite: a deliberate leak printed the DebugAllocator's warning
  and still exited 0.
  Recorded rather than fixed: the S7 negotiated-PDU mark is an echo of a number the master
  proposed (needs the live fixture re-recorded), and `master_goldens.zig`'s header overstated how
  many marks are recomputed from the fixture — both now say so where they appear.

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

  That leftover piece is now done too. Two new private helpers, shared by both server
  shapes — `readData` (`serveTcpOn`'s and `serveTcpMulti`'s `readVec`) and `writeAllChecked`
  (`flush`'s and `writeTo`'s `writeAll`) — consult `reader.err`/`writer.err` before falling
  back to the prior behavior, reusing the `Canceled` variant `tcp.Error` already carries
  rather than adding a second one. `readVec`/`writeAll` sit behind `readable`'s poll gate, so
  it is tempting to assume the poll-side fix already covers them, but it does not: `readVec`
  reaches `std.Io`'s own network read (a genuine, cancelable call, unlike the raw poll)
  whenever more is asked for than is already buffered, which is always true here — the
  request always spans the whole remaining read buffer. A new test drives the shared
  `readData` directly against a silent peer, the same probe shape as the poll-based tests
  above but parked in the read itself rather than the readiness wait in front of it (mutated:
  `expected error.Canceled, found 0`; restored: green, 84/92, 8 skipped — the skips are the
  pre-existing env-gated live-device tests, unrelated to this change). The write side
  (`writeAllChecked`, used by `flush` and `writeTo`/`flushMulti`) has no dedicated test, for
  the same reason `flushUdp`'s send-side fix above has none: reliably parking a thread inside
  a blocking TCP write long enough for a cancel to land needs a full kernel send buffer, not
  reproducible here — it was made by inspection and symmetry with the read side instead.
- **2026-08-11** — Security audit: seven findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on ModbusPal / Kepware simulator
  (design ref); composes `netsim` + 7 protocol responders (design reference, not a test
  anchor).
- **2026-07-23** — New module: In-process simulated device fleet — hosts many protocol
  responders (Modbus, DNP3, IEC 104, S7comm, BACnet, EtherNet/IP, OPC UA) as addressable
  nodes on one deterministic, time-injected scheduler.
