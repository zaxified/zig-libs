# dns — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** tests only. The `tcpExchange` cancel test
  canceled after a fixed 100 ms sleep. On a loaded machine that could land in the connect instead,
  and the test then passed by a different `Canceled` arm. It now cancels once the transport is
  inside its length read (`ReadCueIo`, a `std.Io` double that counts `netRead` entries). It also runs
  unbounded (`timeout_ms = 0`): with the default, `runBounded` answered the cancel itself, and a
  mutated length-read arm stayed green.

- **2026-09-12** — **A1 fix campaign round 2, fixer slot `c`: F7, F10 closed (Q7).**
  - **F7 — additive:** `Record` gains `labels: []const []const u8 = &.{}`, the owner name's
    actual wire label boundaries as slices into `Record.name`, populated by `decode` for every
    record. Closes the audit's demonstrated collision: `\x01a\x01b\x01c\x00` (3 labels),
    `\x05a.b.c\x00` (1 label) and `\x03a.b\x01c\x00` (2 labels) all decode to the identical text
    `"a.b.c"`, but now carry `.labels` of length 3, 1 and 2 respectively — recoverable structure
    a consumer that needs true label counts (the sole consumer, `dnssec`) no longer has to guess
    at by counting dots. `Question.name` and RDATA-embedded names (CNAME/NS/PTR/MX/SOA/SRV
    targets) stay text-only — nothing reads their label structure, so nothing pays for it.
    New test "decode: Record.labels carries the wire structure text collapses (audit F7)"
    reproduces the exact three-record collision. RED (label-span write mutated to a no-op):
    compile succeeds, run crashes (`index out of bounds`, reading the never-initialized span
    buffer) — a legitimate failure, not a compile error. GREEN: `scripts/modtest dns`: 67/67
    (base 64; +2 F10's own tests below, +1 this one).
  - **F10 — BEHAVIOURAL, not breaking:** `config.ResolvConf.timeout_s`/`.attempts` were parsed,
    capped and tested but never read outside `config.zig` — an administrator's
    `options timeout:1 attempts:1`, written specifically to bound the F5 amplification (7
    minutes at the shipped defaults), was silently ignored. Q8 (round 2): chosen — honor
    resolv.conf when `Options.timeout_ms`/`.attempts` are left at their own struct defaults
    (now named `default_timeout_ms`/`default_attempts`) AND resolv.conf is in play (no explicit
    `Options.servers`); an explicit non-default value always wins. New
    `effectiveTimeoutMs`/`effectiveAttempts`, wired into `attemptDeadline` and `query`'s attempt
    loop — the one seam both the UDP receive bound and the TCP `runBounded` cancel already went
    through, so DoH (whose `total_timeout_ms` is set once at `init`, before resolv.conf is ever
    read) is deliberately untouched. RED: unit test on the two helpers, mutated to ignore `conf`
    entirely — `expected 1000, found 5000`; end-to-end test (a real bound-but-silent loopback
    UDP socket plus a resolv.conf fixture with `timeout:1 attempts:1`) — elapsed time exceeded
    the 5 s bound (old shape: 2 attempts × 5000 ms = 10 s). GREEN: both pass, `scripts/modtest
    dns`: 67/67, Debug and ReleaseFast.

- **2026-09-10** — **A1 fix campaign, F13.** A UDP reply bigger than the resolver's receive buffer
  used to be decoded truncated instead of retried over TCP whenever the server sent it without
  setting the TC bit — a real server does set TC when it knows a reply will not fit, but nothing
  stopped a broken or hostile one from sending an oversized reply and skipping it. `udpExchange` now
  also consults the kernel's own delivery flag (`IncomingMessage.flags.trunc`, `MSG_TRUNC`) and
  `query` retries over TCP on either signal — the TC bit the server set, or the kernel's own verdict
  that the datagram did not fit. Measured: a loopback stub sending a 1800-byte reply with TC clear
  against a 1232-byte `rbuf` — before the fix, `query` decoded the truncated bytes directly and
  never dialed TCP at all (confirmed by running the new test under the pre-fix code: `scripts/modtest
  dns -Dtest-filter=F13` timed out at its 25 s cap, `exit 124`, because the test's silent TCP peer was
  never connected to); after the fix the same scenario reaches TCP and the test passes in \<1 s.
  `test-dns`: 64/64 (was 63). SPEC's Backlog no longer lists this; the "consult `MSG_TRUNC`"
  bullet is done.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** the seven `test "live: …"` leave the module and
  become the program `tools/live.zig` (`zig build live-dns`). They talked to real resolvers —
  recursive UDP and TCP, reverse PTR of `8.8.8.8`, and the three DoH shapes against `dns.google` and
  `cloudflare-dns.com` — and each ended `catch |err| return skipLive(err)`, where `skipLive` printed
  `live dns test skipped: <error>` with `std.debug.print`, i.e. to stderr. `scripts/lib/test-lib.sh`
  treats stderr on an exit-0 step as a failure ("OK-but-stderr -> treated as FAIL"), so a slow DNS
  server turned `test-dns` red and took a 217-module run with it, with nothing in this module
  changed. ⭐ Silencing the print would have been the wrong fix and so would keeping the skip: a
  test that reports success for a run in which it did nothing is the defect, not the noise it makes.
  This is the third module to take the shape `Module.live`'s doc comment describes — `dtls` on
  2026-09-06, this module's own hostile-loopback anchor on 2026-09-07 — the anchor's VALUE replays
  hermetically in the lane that runs everywhere, the anchor's TAKING is a program. Nothing is lost:
  `zig build live-dns` runs all seven and reports which of the module or the network is suspected
  (7/7 green when this was written), and `zig build check-interop` compiles it so it cannot rot
  unnoticed. `test-dns` is now 63 tests, none of which reaches the network. Also here: the loopback
  listen in `test "tcpExchange: a canceled blocking read surfaces Canceled"` no longer skips with a
  stderr print — an ephemeral loopback bind that fails is a broken environment, and the honest
  report is a failure.

- **2026-09-08** — **NO CONSUMER-VISIBLE CHANGE:** the question-check anchor is split into a
  hermetic half and a live one (audit F20). `test "query: a reply whose question is not ours is
  not the answer, over loopback"` bound a UDP socket, spawned a stub on a second thread and then
  read that stub's `served` counter — from the test thread, while the stub was still runnable,
  because the joining `await` was a `defer`. It failed twice in the wild, always as
  `expected 1, found 0`, and reproduced here at **10 failures in 20 runs** on 8 cores under 32 busy
  loops. ⭐ The resolver was right every time: `found 0` on the counter means the datagram HAD been
  received and rejected, so what failed was the measurement, not `dns`. What the test asserted about
  parsing is now the test "decodeResponse: the replies interop-dns captured off a real socket",
  replaying `src/testdata/reply_wrong_question.bin`, `reply_no_question.bin` and — as the positive
  control — `reply_honest.bin`; it schedules nothing and passed 30 of 30 under the same load, as did
  the whole 70-test suite 10 of 10. What genuinely needs a socket is now the program
  `tools/interop.zig` (`zig build interop-dns`, no peer and no network; `-- --capture` re-takes the
  frames), compiled by `check-interop` and run by `scripts/test.sh interop`. The same
  read-before-join was fixed in the surviving TC-bit test, which had only ever been saved by the
  300 ms the resolver spends in the TCP path afterwards. `dns` was deliberately NOT added to the
  serial `live` set: an unsynchronised cross-thread read is not a scheduling accident, so serialising
  the module's other 69 tests would have bought a quieter race rather than a fixed one.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the local `fuzzSeed` /
  `fuzzSeedInto` copies in this module's fuzz files are now `testkit.fuzz`. The
  helper existed **33 times across 12 modules in three shapes**, each carrying its
  own note about the same trap (the returned array has to be container-level or
  the slice dangles with the right length and garbage behind it). Proved
  byte-identical to the copies it replaces before they were deleted, and the
  comparison test was itself broken on purpose first to show it was not vacuous.
  `testkit` added to this module's `test_deps`; test-only, nothing a consumer
  imports changed.

- **2026-09-06** — A1 security audit, the four HIGH findings fixed. **Consumer-visible
  behaviour change (stricter acceptance, no new error values):** `Resolver` now refuses a
  reply that does not echo exactly our question — one question, our name (ASCII
  case-insensitive), our type, class IN — as `error.MalformedResponse` (RFC 5452 §9.1;
  before, id + QR bit was the whole check, so a reply whose question section named
  `attacker.example TXT`, or had no question section, was taken as the answer to
  `example.com A`). `lookupIp` and `reverse` return only records whose owner is the
  queried name or a CNAME target chained from it inside the same answer section (8 hops
  max; a reply to `example.com` carrying `victim.test A 203.0.113.66` used to yield that
  address). `resolve`/`query` are unchanged in what they return. `timeout_ms` now bounds
  each TCP attempt end to end — connect, write, length read, body read — by running the
  exchange on its own task and canceling it at the deadline (`runBounded`, the
  `http.Client` construction); before, only UDP was bounded, and a server that accepted
  the connection and never answered held the caller until the OS gave up (measured 45-60 s
  at `timeout_ms = 1000`), reachable on the default `.auto` transport by one TC-bit
  datagram. An `Io` with no unit of concurrency fails such an attempt as `NetworkFailed`
  rather than run it unbounded. `queryJson` validates `name` by the wire path's rule
  (`BadName`/`NameTooLong`) and percent-encodes it into the URL (`&`, `=`, CR, LF, space,
  `%` were passed through into the request line). A fresh transaction id is drawn for every
  datagram sent, not once per `query`. `Error.Timeout`'s doc now states the real budget
  (`timeout_ms × attempts × servers` per query, more for `lookupIp`) instead of
  `timeout_ms × attempts`. Tests: correlation, bailiwick (incl. out-of-order chain, loop,
  over-long chain), URL encoding, hostile section counts under a 4 KiB memory limit (the
  old test accepted `Truncated` from a decoder that had first allocated 8.6 MB), SOA/MX
  RDLENGTH shorter than their fields, and loopback stubs — a UDP server that lies about the
  question or slips in an off-bailiwick record, a TCP server that accepts and never
  answers, via both `.tcp` and the TC-bit path. The fuzz harness draws one `smith.slice`
  and is seeded with the six live captures (it had decoded the empty packet once per run).
- **2026-08-23** — **Breaking:** `reverseName` returns
  `ReverseNameError![]const u8` (`error{OutputTooSmall}`) instead of
  `[]const u8`. It used to guard `buf.len >= max_reverse_name_len` with
  `std.debug.assert`; the `std.Io.Writer.fixed` writes inside stay
  memory-safe regardless (they clamp to the buffer), but every one is
  `catch unreachable`, so ReleaseFast compiling the assert out turned a
  too-small `buf` into undefined behaviour (an `unreachable` hit) instead of
  a clean failure. Found by an audit sweep for this shape. `Resolver.reverse`
  and the example's `-x` path both size their buffer to exactly
  `max_reverse_name_len`, so the new error is provably unreachable there
  (`catch unreachable`).
- **2026-08-23** — `sortIps` no longer re-checks
  `netaddr.max_sort_candidates` before calling `sortDestinations`; the bound is
  enforced inside `netaddr` now that it returns an error, so the rule lives in
  one place. Behaviour is unchanged: an answer set larger than the bound is
  left in arrival order.

- **2026-08-22** — `tcpExchange` (the only place in this file that owns a TCP fd directly)
  used to fold every write (`writeInt`/`writeAll`/`flush`) and read (`takeInt`/
  `readSliceAll`) failure into `error.NetworkFailed`, including a canceled `std.Io` wait —
  `Io.Reader.Error`/`Io.Writer.Error` cannot carry `Canceled` at all, so the reason was gone
  by the time it reached the `catch`. Two new private helpers, `readFailure`/`writeFailure`,
  consult the concrete `Stream.Reader`/`Stream.Writer`'s out-of-band `err` field first and
  reuse the `Canceled` variant `Error` already carried — the surrounding `query()` callers
  already special-case `error.Canceled` on `tcpExchange`'s result, so no caller-side change
  was needed. `udpExchange` needed nothing: `Socket.Send`/`ReceiveTimeoutError` already carry
  `Io.Cancelable` intact, and every catch there already had an explicit `error.Canceled`
  arm. A new test drives `tcpExchange` against a loopback listener nobody ever accepts —
  `connect` and the length-prefixed write both still succeed (the kernel completes the
  handshake and buffers the write), so the read genuinely parks in `takeInt` (mutated:
  `expected error.Canceled, found error.NetworkFailed`; restored: green, 59/59). The write
  side (`writeFailure`) has no dedicated test, for the same reason a UDP send-side fix
  elsewhere in this collection has none: reliably parking a thread inside a blocking TCP
  write long enough for a cancel to land needs a full kernel send buffer, not reproducible
  here — it was made by inspection and symmetry with the read side instead.

  Audited but left alone: `acme`'s six `catch return error.X` sites named for this pass are
  all either over in-memory buffers (`std.Io.Writer.Allocating`, PEM/URL string encoding —
  no fd, nothing to lose) or already correctly widen `http.Client`'s errors through
  `mapHttpError`, which has an explicit `error.Canceled` arm; its one direct `Cancelable!void`
  call (`Client.sleepMs`'s `d.sleep`) already returns exactly `error.Canceled` on the only
  error it can produce. `dns`'s own `ensureConfig`/`readHosts` (local `/etc/hosts`/
  `resolv.conf` reads) were not touched either — a different site from the one named for this
  pass, local disk I/O rather than a TCP/UDP transport, and out of scope for this change.

  Found but out of module scope, not fixed here: `http.Client.Response.readAllAlloc`
  (`modules/http/src/Client.zig`) declares `Canceled` in its `Error` set but its own `catch
  |err| switch (err) { ..., else => error.ReadFailed }` never consults the concrete reader's
  `err` field, so a body-read cancellation cannot currently reach a caller through it at all —
  `dns`'s `dohExchange`/`queryJson` inherit this (their own `readAllAlloc` catches were left
  as `else => error.DohFailed` rather than given an `error.Canceled` arm, since one would be
  unreachable dead code against `readAllAlloc`'s current behavior and pure churn against
  CONVENTIONS.md's own "don't fix what can't see a cancel" guidance). Surfaced here since it
  was found auditing this module's DoH paths, but the fix belongs in `http`.
- **2026-08-18** — Re-export `message.max_query_len`, `message.QueryOptions` and
  `message.EncodeError` from the module root, so a codec-only consumer sizing/calling
  `encodeQuery` never has to name `dns.message` directly (which would put `Resolver`,
  and therefore the `http` dependency, in its import graph for no reason).
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Live-tested against real
  UDP/TCP/DoH/DoH-JSON resolvers over the network (decode/encode vectors are
  self-authored, not captured).
- **2026-07-02** — New module: RFC 1035 resolver —
  A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA over UDP/TCP + DoH.
