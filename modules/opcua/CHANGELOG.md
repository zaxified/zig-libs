# opcua — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** `decodeArray`/
  `decodeVariantArraySlice` (private, services.zig/encoding.zig) now take a
  `freeItem` so a truncated wire array frees what it already decoded instead
  of leaking it (C4); five `nodestore.zig` `dup*` helpers now free an
  earlier allocating step if a later one fails with OutOfMemory (C7); new
  `pub fn freeRelativePath`/`freeBrowsePath`/`freeBrowsePathResult` fill a
  pre-existing gap (those three types had no free function at all) needed
  to wire C4's fix through `RelativePath`/`BrowsePath`/`BrowsePathResult`
  arrays — additive, nothing existing calls them yet. `Config.max_lifetime_count`
  (new field, default 10 000) caps `CreateSubscription`'s `LifetimeCount`,
  which previously had a floor and no ceiling (C5) — additive default,
  existing callers unaffected. Catalog `.doc` line and `SPEC.md` corrected
  to match the code (C6, C8).
- **2026-09-07** — Both fuzz targets had been running one fixed input for their whole
  existence. `security`'s certificate target was written as an inline
  `struct { fn run … }.run` — the one shape `check-fuzz-reach` reports as UNJUDGED rather
  than judging, and it carried exactly the defect the gate names elsewhere: `smith.bytes(&buf)`
  followed by `smith.valueRangeAtMost(u16, 0, 1024)`, whose ranged draw returns the range
  MINIMUM because `bytes` has already eaten the octets it needs, so `certificatePublicKey`,
  `certificateValidity` and `viewAsymmetricHeader` were each called with the empty slice and
  nothing else. `server`'s `fuzzConnection` was worse: its first draw was `smith.value(bool)`,
  which is a 1-bit range, so `rig.connect()` had **never run once** outside `--fuzz` and the
  service layer the target names was unreachable, while all four of its per-round lengths were
  0 — it fed the connection state machine nothing, four times, from a cold rig. Both are now
  byte-first `smith.slice` draws with a real corpus and a corpus guard; the connection knob
  moved INTO the drawn script (first octet), because a knob drawn after the byte draw is dead
  on a replay. Measured: **certificates 0 of 12 seeds non-empty, 0 parsed, 0 OPN headers
  scanned → 11 of 12 non-empty, 1 parsed, 1 scanned; connection 0 of 8 scripts fed a byte and
  0 replies → 8 of 8 fed, 6 replies, 4 from a live session.** No behavior change.
- **2026-09-07** — The Python `asyncua` interop left the module. It had been a
  ~190-line driver script held as an inline `\\` string literal in
  `src/server_interop.zig` and run with `python3 -c`, so `zig build test-opcua`
  reached for an interpreter and a third-party package the module has no
  business needing, and the anchor skipped — loudly, but skipped — wherever
  either was absent. That is the seventh instance of the shape six modules were
  separated from on 2026-09-06 (`f3dbf38d`, `f42cc67a`); it was missed because
  the other six kept their driver in a FILE, which could be `git mv`'d and was
  therefore visible in the diff, while a string constant moves nowhere.
  `zig build check-module-purity` (`33f26907`) is what named it.
  - The script is now `tools/asyncua_driver.py`, run **from its own path** —
    never embedded, never inlined — by `tools/interop.zig`
    (`zig build interop-opcua`, compiled on every lane by
    `zig build check-interop`).
  - `zig build interop-opcua -- --capture` records the whole exchange into
    `src/testdata/asyncua_transcript.txt`, and the new `src/asyncua_replay.zig`
    replays it **byte for byte with no interpreter, no asyncua, no child process
    and no socket**: seven connections at #None / Basic256Sha256 Sign (encrypted
    username token) / SignAndEncrypt, covering Hello, OpenSecureChannel,
    GetEndpoints, CreateSession, ActivateSession, Browse, Read, Write, Call,
    CreateSubscription, Publish and two mid-stream SecurityToken renewals.
  - Nothing was weakened to make that replayable. The seams were already there:
    `Server.init` takes the `std.Random` it draws from, and `feed`/`tick` take
    time as a parameter, so a recorded seed plus `start_time` plus each `t=`
    fixes the RSA key pair, the certificate, every nonce, token id and
    timestamp. The transcript header carries all of it, plus the asyncua and
    Python versions, the date and the exact command.
  - Coverage went UP, not down. The live test compared ten stdout markers, the
    driver's exit status and a connection count — twelve facts. The replay
    requires every one of the server's 1 734 recorded answers to match exactly
    (which pins Browse, Read, Write, Call and the DataChangeNotification through
    their ciphertext), re-derives each connection's SecurityPolicy/SecurityMode,
    walks the opc.tcp framing of both directions, decodes the endpoint list off
    the unsecured leg and requires our own certificate on the secured
    endpoints, and checks the value asyncua wrote is still in the address space.
    Proved not blind by mutation: a single flipped transcript byte, a dropped
    renewal leg, a falsified SecurityMode and a one-value change to
    `Config.max_chunk_count` each turn it red.
  - What the replay CANNOT do is stated in its own header and in SPEC.md: it
    cannot find a NEW divergence, it cannot tell "we broke interop" from "we
    changed valid bytes", and it cannot re-check anything that was not bytes on
    the wire (asyncua's own assertions and its exit status are kept in the file
    as `#` notes for that reason).
  - Unchanged and deliberately not folded in: the `podman`/open62541 tests still
    run a container. A third-party *server* is a live PEER, not a foreign
    toolchain, and `live` in `build.zig`'s `module_list` is where that question
    is answered.
- **2026-09-02** — Security audit: a plaintext `UserNameIdentityToken` is now
  refused unless the client named a `UserTokenPolicy` this server advertises
  **and** that policy is `#None`. The refusal used to be nested inside
  `if (parsed.policy_id) |pid|` and `if (userTokenPolicy(cfg, pid)) |policy|`,
  both of which fall through when absent — so a token carrying no PolicyId, or
  naming an unadvertised one, had its cleartext password accepted against an
  endpoint whose only username policy demands encryption. The module's own test
  for this passed the one PolicyId that reaches the guard, so it proved the
  branch works without proving the branch is reached.
- **2026-09-02** — Security audit: `SamplingInterval` is clamped at both ends
  (new `Config.max_sampling_interval_ms`). It had a floor and no ceiling, unlike
  `reviseInterval` and `reviseKeepAlive` beside it, so a client-supplied
  `Double` of 1e300 came back verbatim and was then added to a millisecond clock
  as an `i64`: a remote panic in Debug and ReleaseSafe, and in ReleaseFast an
  `i64` poison value that made `now_ms < next_sample_ms` never true — the item
  sampled on EVERY tick while the server reported
  `RevisedSamplingInterval = 1e300`. Asking for the slowest interval got you the
  fastest, the exact inverse of what `min_sampling_interval_ms` enforces. Both
  `CreateMonitoredItems` and `ModifyMonitoredItems` route through the clamp.

- **2026-09-02** — Security audit: **a `SecurityPolicy#None` channel was accepted by
  a server that advertises no `#None` endpoint.** `endpointOffers` — documented as
  "The gate every `OpenSecureChannel` passes through", with `Config.endpoints`
  documented as "**This list is the authority**" and SPEC promising "only
  advertised modes are usable" — was only reached on the secured branch of
  `handleOpenSecureChannel`; the `#None` branch returned before it. A deployment
  built the documented way for security, offering Basic256Sha256 at Sign and
  SignAndEncrypt and nothing else, therefore still accepted a cleartext channel;
  and since `CreateSession` and `ActivateSession` both gate their certificate and
  `ClientSignature` checks on `sec_mode != .none`, both were then skipped, giving
  an anonymous peer Read/Write/Call in the clear. The gate now applies to both
  branches.

- **2026-08-15** — Test-only (no change to the module): the driver rejected a reconnect it
  should have accepted, under load. In one iteration of `Driver.serve` the order was *read
  data → accept → tear down a finished connection*, so when a client's last bytes
  (`CloseSecureChannel`) and its FIN landed in DIFFERENT poll iterations — which contention
  makes likely — the accept branch still saw a non-null `stream` and closed the incoming
  connection. open62541's `client` and `client_encryption` both connect, call GetEndpoints,
  disconnect and reconnect, so both reported `Receiving ACK message failed with
  BadConnectionClosed`. The teardown now runs before the accept branch, so accept decides on
  the current state rather than on state that changes later in the same iteration.

  ⚠ This is the SECOND time closing one hole in this loop opened another: the 2026-08-14
  reorder fixed the case where the close arrives as a 0-byte read in the same poll as the
  next connection, and its comment claimed the failure mode was solved. It was solved for
  one of the two ways to reach it.

  Reproduced deliberately rather than waited for: running the four live modules
  CONCURRENTLY under 7-of-8 cores of load failed 3 of 3 rounds (2, 3 and 2 failures of 176);
  after the fix, 4 of 4 rounds pass 176/176. That condition is what the serial `LIVE_MODULES`
  step had been hiding — and in the same experiment `ssh`, `dtls` and `imap` passed every
  round, so of the four modules quarantined there, only this one had evidence against it.
- **2026-08-15** — Test-only (no change to the module): one live test spent two minutes
  waiting out a backstop. `Driver.serve` could only end early through a CLOSED connection —
  `peer_alive` is consulted in the branch guarded by `stream == null` — and open62541's
  `client_subscription_loop` opens one connection, subscribes and stays, so the question was
  never asked and the loop ran to `deadline_ms = 120_000`. Measured by watching the
  container: alive from t=12 s to t≈120 s of a 177 s module, on every lane and every local
  gate run since the test was written. New `Driver.StopWhen` is asked on a timer regardless
  of connection state, and the subscription test hands it the line its own assertion counts
  (`currentTime has changed`, ×2) — the client's own output rather than a server-side
  publish counter, because the point of driving a third-party client is that it UNDERSTOOD
  what we sent. `deadline_ms` is deliberately unchanged: it is a backstop, and lowering it
  would have hidden this instead of fixing it. **Module: 177 s → 57 s**, 176/176 passing,
  three consecutive runs at 57/57/57 s with no leftover containers.
- **2026-08-13** — Test-only: deleted `test "smoke"` in `src/root.zig`, whose
  whole body was `try std.testing.expect(true);`. **Neither BREAKING nor
  BEHAVIOURAL** — no production code changed. It could not fail, and it
  anchored nothing: `root.zig` is this module's test root, and the aggregation
  `test` at the top of that file is what pulls the submodules' tests in. Its
  only effect was to report a test count one larger than the coverage behind
  it. Deleted rather than given an assertion because the spot has no subject
  of its own — the offline-flow test that follows it is the real smoke test.
  Measured: `zig build test-opcua` went 176/176 to 175/175, the difference
  being exactly this test, with every other test still running and passing.
- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).
