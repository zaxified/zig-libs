# http — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `Server`'s per-connection reader and writer stop reporting a
  canceled connection as a stalled peer. Internal change, no API surface moved:
  `Client` already carried `Canceled` in its `Error` set and already recovered it
  from `Conn.sr.err`/`Conn.sw.err`, and `BindError`/`ServeError` already carried it
  for the listener — the connection path was the half that did not. Two distinct
  blind spots.
  **(1) The stall timeouts are raw `poll(2)`, which is not a `std.Io` cancelation
  point at all.** `std.posix.poll` restarts itself on `EINTR`, and a thread parked
  in a syscall `std.Io` never registered is not signalled in the first place — so a
  `Group.cancel` over the connection tasks (the shutdown a consumer running `serve`
  on its own task performs) left every idle keep-alive connection sitting out its
  full `read_timeout_ms`, and then filing itself as `timed_out`: a slowloris, by the
  server's own account. `TimeoutReader.streamFn` and `TimeoutWriter.pollOut` now ask
  `Io.checkCancel` once the wait ends, on the timed-out **and** the poll-failed path.
  **(2) Past the poll, the reason was flattened.** `Reader.StreamError` /
  `Writer.Error` cannot carry `error.Canceled`, so std parks the real cause on the
  concrete `net.Stream.Reader.err` / `.Writer.err`; both wrappers now take the
  concrete socket reader/writer instead of a bare interface and consult that field
  in `readFailure`/`writeFailure` before mapping.
  Because neither vtable's error set can be widened, the recovered verdict is
  recorded out of band in `canceled`, beside the existing `timed_out` and for the
  same reason std does it — and deliberately *beside* it, not folded into it: a peer
  that stopped talking and a connection its own server abandoned are different
  events. Four tests, one per fixed path (read/write × poll/socket), each confirmed
  to fail with its own fix reverted and to pass with it restored.
  `h2_server.serve`/`serveStream` are untouched: they take a caller-supplied
  `*Reader`/`*Writer` and own no fd, so they have no concrete reader to ask. Served
  over `Server`'s own socket (`enable_h2c`) they get the fixed wrappers for free;
  used as the BYO-TLS entry point, recovery belongs to whoever owns the transport.
- **2026-08-22** — `proxy` sizes its address-formatting buffer as
  `netaddr.max_ip_text_len` rather than a hand-picked 64, following `netaddr.formatIp`'s
  new fixed-size parameter.
- **2026-08-18** — test/tooling only, no API change. Closed two gaps an audit of the
  two entries below found.
  **(1) Regression tests for the Plain-side `owned` double-free fix.** The entry below
  added dedicated crash-reproducing tests for `requestInner`/`requestStreaming`
  (`"pool: stale-conn retry whose redial ALSO fails does not double-free conn"` and the
  `requestStreaming` counterpart); `requestInnerPlain`/`requestStreamingPlain` got the
  identical `owned`-boolean fix one commit earlier (caught pre-commit when it segfaulted
  a test during development) but shipped with no test of their own that would catch a
  regression. New tests `"requestPlain: pool: stale-conn retry whose redial ALSO fails
  does not double-free conn"` and `"requestStreamingPlain: pool: stale-conn retry whose
  redial ALSO fails does not double-free conn"` mirror the existing pair exactly, reusing
  the same raw-socket origins (`staleConnNoRedialOrigin`/`staleConnRstNoRedialOrigin` —
  already TLS-free, so nothing about the origin changes) — the streaming one needs the
  same treatment its TLS-side counterpart did: `staleConnRstNoRedialOrigin`'s hard
  `SO_LINGER{onoff=1,linger=0}` RST plus `write_buffer_size = 8`, because
  `requestStreamingPlain`'s retry fires only off a **write** failure and a plain FIN
  close does not fail a small buffered write. Verified in both directions, the way the
  entry below did: reverting each `owned = false;` alone reproduces the exact
  double-free — a segfault inside `Conn.destroy`, called a second time from
  `errdefer if (owned) conn.destroy();` — and restoring both is green.
  `zig build test-http` — 444/444 pass, native, `-Doptimize=ReleaseFast` and
  `-Doptimize=ReleaseSafe` both included.
  **(2) `modules/http/sizeprobe/` is now gated.** It is the only proof of the plaintext
  split's central claim (zero TLS symbols, ~325 KB saved — see the split's own entry
  below) and had its own standalone `build.zig` that nothing in the repo referenced: not
  the root `build.zig`, not `scripts/test.sh`, not CI — an artefact whose check never
  runs is worse than none, because it still looks authoritative. `scripts/
  check-http-sizeprobe.sh` wires it into `scripts/test.sh` beside the other `check-*`
  steps (all three call sites: `harness_smoke`, `cmd_changed`, `cmd_all`/`cmd_build`).
  Chosen level: build BOTH probes (catches rot in either) for `x86_64-linux-musl` only,
  and assert `probe_after_syms` links **zero** TLS/certificate/curve/hash symbols — the
  property that actually matters and is stable under unrelated code churn, not an exact
  byte count that drifts for reasons unrelated to this property and gets disabled once it
  starts failing. One target, not the two `sizeprobe/run.sh` cross-builds for the
  measured size delta: the property under gate is a Sema *reachability* fact (does the
  plaintext call graph name a TLS/crypto decl at all), which does not vary by
  architecture the way the 32-bit/big-endian bugs `check-portable` hunts for do, so a
  second cross-compile would double this gate's wall time for zero additional coverage
  of what it asserts; the mips-linux-musleabi leg and the byte-count table stay in
  `run.sh`, run by hand before a tag. ~30s when `Client.zig` (or anything it pulls in)
  actually changed content, near-instant otherwise (Zig's own build cache); silent on
  success, since `scripts/test.sh`'s `step` treats any stderr as a FAIL even at exit 0.
  Verified it fires: temporarily made `dialPlain` reach `ensureCaBundle()` behind a
  runtime `url.scheme == .https` check (mirroring the original bug's shape — a *runtime*
  branch Sema cannot prove dead) — the gate failed, listing the linked `Certificate`/hash
  symbols by name; reverted, gate green and silent again.
- **2026-08-18** — **BEHAVIOURAL, not breaking** — fixed the double-free the entry
  below left in place in the shipped `requestInner`/`requestStreaming`: a dial
  failure immediately after the stale-connection retry's `conn.destroy()` left
  `errdefer conn.destroy()` armed over an already-freed `conn`, so the errdefer
  fired again on the same pointer. Reproduced directly for both functions
  (not just reasoned from the shape): a raw-socket test origin serves one
  request then hangs up, so the pool hands the next call a stale connection;
  the listener is then closed before the retry's redial, forcing that redial
  to fail too. Against the pre-fix code this segfaulted inside `Conn.destroy`
  — called a second time from the `errdefer` — in both `requestInner` (via
  `client.request`) and `requestStreaming` (which needed a tiny
  `write_buffer_size` to force the request head's buffered write to actually
  hit the socket, since the ordinary 4 KiB buffer never drains for a head
  that small). Fixed with the same `owned`-boolean idiom the plaintext path
  already used (`errdefer if (owned) conn.destroy()`, `owned` toggled around
  each explicit `conn.destroy()`), so the module now has one double-free-safe
  idiom instead of two. While re-reading `requestInner`'s redirect branch for
  the same shape, found a second, independent instance: `conn.destroy()` ran
  *before* `url = http.Url.parse(resolved) catch return error.BadRedirect;`,
  so a redirect `Location` header that resolves to text `Url.parse` rejects
  (a live, peer-controlled input — `resolveLocation` copies an absolute
  `http(s)://` Location through verbatim, only length-checked) hit the same
  bare-errdefer-over-a-freed-`conn` bug. Reordered to parse before
  destroying, matching the ordering `requestInnerPlain`'s redirect branch
  already used. Swept the rest of the module for the same
  `conn.destroy(); … try …` shape (`connectH2c` and everywhere else that
  dials): no other instance found — every other fallible dial in the module
  is a first-ever dial with nothing already destroyed to double-free.
  **What changes for a caller of `Client.request`/`requestStreaming`:** in
  the narrow case of a redial-after-stale-detect failing, or a malformed
  absolute-URL redirect target, the call now returns the ordinary typed error
  (e.g. `error.ConnectFailed`, `error.BadRedirect`) instead of the process
  crashing or corrupting the allocator via a double-free — no API/signature
  change, and every other path is untouched. Pinned by two new regression
  tests (`"pool: stale-conn retry whose redial ALSO fails does not
  double-free conn"` and the `requestStreaming` counterpart); `zig build
  test-http` — 442/442 pass, `-Doptimize=ReleaseFast` included.
- **2026-08-18** — **ADDITIVE** — `Client` gains a plaintext-only call graph:
  `requestPlain`/`requestStreamingPlain`/`putFilePlain` mirror
  `request`/`requestStreaming`/`putFile` exactly (redirect/retry/pooling
  behavior unchanged) but return `error.UnsupportedScheme` for any
  `https://` URL — direct or via a redirect hop — instead of dialing TLS.
  `request`/`requestStreaming`/`putFile` themselves are **source- and
  behavior-unchanged**; `dialConn` is now a two-line dispatcher onto two new
  private decls, `dialPlain` and `dialTls` (split out of its former single
  body), and those two existing entry points still go through `dialConn`
  exactly as before.
  - **Why:** a consumer (a device agent on an 8 MB router overlay)
    measured `http.Client` at **+351 000 B (+49%) on x86-64
    musl/ReleaseSmall and +607 200 B on big-endian MIPS32** for two
    plaintext one-shot operations (a `putFile` upload, a `request` +
    `streamRemaining` fetch, both to an IP literal, no TLS/redirects/reuse).
    A follow-up measurement attributed 89.8% of that (325 760 B) to one
    cause: `dialConn` computed `tls_needed` from a *runtime* URL value, so
    its `if (tls_needed)` branch forced Sema to analyse the whole TLS client
    (handshake state machine, X.509 parse/verify, every hash/curve/AEAD it
    pulls in) for every caller regardless of which branch ever actually ran.
    Refactoring the branches *inside* `dialConn` was tried first and does
    not help — a dispatcher that still names both `dialPlain` and `dialTls`
    keeps both reachable from anything that calls it. Only a caller that
    never mentions the TLS-side decl at all — the new entry points — drops
    the reference; this is the same mechanism that already gives HTTP/2
    (`connectH2c`, its own entry point `dialConn` never calls) zero cost
    when unused.
  - **Measured:** `modules/http/sizeprobe/` (a standalone probe, not wired
    into `zig build` — see its README) builds static `ReleaseSmall`
    executables performing the same two call sites that consumer measured, once
    through the TLS-capable entry points and once through the new
    plaintext-only ones: **324 888 B saved on x86-64-linux-musl** (within
    1 KB of the 325 760 B predicted for "the TLS reference" alone) and
    **685 328 B saved on mips-linux-musleabi** (big-endian MIPS32). `nm` on
    an unstripped build of the plaintext-only probe shows **zero**
    `tls.Client`/`Certificate`/curve/hash symbols on either target (the same
    grep matches 196 symbols on the TLS-capable probe, proving the grep
    itself is not vacuous).
  - **A real bug found and fixed along the way, scoped to the new code
    only:** the naive port of `requestInner`/`requestStreaming`'s
    stale-connection-retry shape (`conn.destroy(); conn = try
    c.dialPlain(url);` inside a scope still covered by `errdefer
    conn.destroy()`) double-frees `conn` if the redial fails, or — new to
    the plaintext path — if a same-scope scheme check on a redirect target
    returns an error after the old connection was already destroyed. Fixed
    in `requestInnerPlain`/`requestStreamingPlain` with an explicit `owned`
    boolean guarding the `errdefer`, and the redirect-scheme check was
    reordered to run *before* `conn.destroy()` rather than after. **The
    same latent shape exists in the shipped `requestInner`/
    `requestStreaming`** (a dial failure immediately after the
    stale-connection retry's `conn.destroy()`) — left untouched per this
    change's no-behavior-change constraint on existing callers; narrow and
    only reachable when a redial right after a stale-pooled-connection
    failure itself fails.
  - **Regression guard, honestly scoped:** a Zig test
    (`"requestPlain/requestStreamingPlain/putFilePlain: https:// is
    rejected before any dial"`) proves the *behavioral* half —
    `error.UnsupportedScheme` and `dialCount() == 0`, i.e. no socket ever
    opens — plus loopback functional tests prove the plaintext path
    actually works (GET/POST/PUT-a-real-file, pooling). No Zig test can
    prove a symbol's *absence* from a differently-scoped binary — that is
    what `sizeprobe/` is for, and it is not part of `zig build test-http`.
  - Docs: README.md gains a "Plaintext-only client" subsection under
    "Client API" plus a bullet in "Client behavior notes"; SPEC.md's design
    section and Verification section both gain an entry.

- **2026-08-18** — **BREAKING (narrow)** — three fail-open `std.debug.assert` guards on
  caller-supplied sizing became checked errors / a defensive restructure, the same
  `reset()` shape as the 2026-08-13 entry below: `assert` is `if (!ok) unreachable;`,
  compiled to nothing in `ReleaseFast`/`ReleaseSmall`, so each was a precondition that
  held only in the modes nobody ships.
  - `range.zig`'s `MultipartRanges.writeBody` — this morning's `7dff02d` added
    `std.debug.assert(r.end < data.len)` ahead of `data[r.start..r.end+1]` as a guard
    against a caller passing `data`/`ranges` resolved against different `total`s (R2 and
    R3 are deliberately decoupled — a `ResolvedRange` set can be resolved long before the
    `data` it is later served against is even chosen). `writeBody` now returns
    `WriteBodyError!void` (`std.Io.Writer.Error || error{RangeOutOfBounds}`), pre-checking
    every range against `data.len` **before** writing anything, so a mismatch fails
    atomically rather than emitting a truncated multipart body. Verified no in-repo caller
    reaches the old bug: `staticfiles` (the module's only in-repo consumer) never calls
    `writeBody` — it falls back to a full 200 on multi-range requests — so this was an
    unsound public API with no live blast radius yet, not a shipped defect.
  - `bufpool.zig`'s `BufferPool.release` — `std.debug.assert(slab.len == p.slab_size)` was
    the only guard against a caller returning a wrong-sized slab into the shared idle
    pool. Restructured instead of erroring: a mismatched `slab` is now freed rather than
    pooled, so `acquire`'s "always exactly `slab_size`" postcondition holds
    unconditionally rather than by caller cooperation — no signature change, `release`
    still never fails. Matters because a bad slab re-entering the pool would surface
    downstream, at `Client.connectH2c`, which trusts an acquired slab's length without
    re-checking.
  - `Client.zig`'s `connectH2c` — `std.debug.assert(bp.slab_size == slab_len)` guarded
    `slab[0..read_buffer_size]` / `slab[read_buffer_size..]`, a fixed-offset split with no
    length check of its own. `Options.buffer_pool` and `read_buffer_size`/
    `write_buffer_size` are two independently caller-supplied config points with no
    type-level link, so a checked error is the right shape here (not a restructure): the
    check now runs before any allocation or I/O and returns the new `Error.
    BufferPoolSizeMismatch`.
  Swept the rest of `modules/http/` for the same shape (an `assert` immediately guarding
  an index/slice/cast of caller-supplied data) and found nothing else load-bearing: every
  other `std.debug.assert` in the module either guards a pure state-machine/protocol
  invariant with no adjacent unchecked memory op (`Server.zig`'s `bind`/`beginGzip`/
  `beginStreaming`, `h2.zig`'s role/window-sign/assembly checks, `h2_server.zig`'s
  `removeJob`, `proxy.zig`'s backend-XOR), or sits ahead of an operation that is
  independently self-bounded regardless of the assert (`h2_client.zig`'s `readBody` uses
  `@min(buf.len, src.len)`; `Client.zig`'s pool reap loop guards `reap_n < max_reap_batch`
  in the loop condition itself; `h2.zig`'s `parseFrame` validates `payload.len` per frame
  type independently of the `payload.len == h.length` assert). Two are flagged for a
  follow-up, not fixed here (out of proportion for this pass — both ripple through
  multiple call sites' signatures/error sets): `h2.zig`'s `FrameHeader.encode`
  (`std.debug.assert(h.length <= max_allowed_frame_size)` ahead of three `@intCast`s that
  shift-and-narrow `h.length` into wire bytes — `encodeRawFrame`, the public primitive
  every frame encoder calls, does not itself bound `payload.len` before handing it to
  `FrameHeader.length`, so a payload over 16 MiB reaches the narrowing casts unchecked in
  `ReleaseFast`); and `Server.zig`'s `ResponseWriter.init`
  (`std.debug.assert(opts.compression == null or opts.gzip_scratch != null)` ahead of
  `beginGzip`'s `rw.gzip_scratch.?` — the one in-repo caller, `serveOne`, already computes
  the safe combination before calling `init`, so this is reachable only via direct
  `ResponseWriter` construction outside `serveStream`, but `init` is `pub` and the two
  `InitOptions` fields have no type-level link either).
  `zig build test-http` — 436/436 pass, native, `-Doptimize=ReleaseFast` included (the
  mode all three old asserts vanished in). Three new tests pin the fixes; each is
  meaningful in every optimize mode, unlike the assert it replaces, because each now
  exercises real control flow rather than a safety check.
- **2026-08-18** — `check-portable` (wasm32-wasi 32-bit probe) fixes, 10 sites across 3
  files, none behavior-changing on a 64-bit host. `http` is a hub dependency (19 `.any`
  modules import it — acme, cookies, cors, grpc, health, idempotency, jwt, mcp-http,
  openapi, ratelimit, requestid, router, security-headers, sessions, staticfiles,
  tracecontext, validate, webhooksig), so `Server.zig:2696`'s `day_names[day.day % 7]`
  (`day.day` is `u47`, indexing wants `usize`) alone was blocking the wasm32 compile of
  all of them. Fixed, plus everything else the wasm32 test-binary compile turned up once
  that first error stopped hiding the rest:
  - `Server.zig:2696` — index with `@intCast(day.day % 7)`. `day.day` stays `u47` (a
    deliberately wide day counter); the `% 7` bounds the *result* to 0..6 before the cast,
    so the narrowing can never truncate real bits regardless of target width — casting the
    bounded result, not the wide field, is the safe direction.
  - `Server.zig:4595`/`:4610`, `h2_server.zig:3218` — `Reader.take()` wants an exact
    `usize`; the caller had a `?u64` `content_length`. `content_length` itself stays `u64`
    (RFC 9110 puts no bound on it, and `ContentLengthReader` streams it rather than
    materializing the whole body) — only these three test call sites, which read a short
    literal body straight into memory, cast down at the call.
  - `range.zig:462` (`MultipartRanges.writeBody`, the only production-code site) + 3
    mirrored test sites — `data[r.start .. r.end + 1]` wants `usize` bounds;
    `ResolvedRange.start`/`.end` stay `u64` (a representation's byte offsets are not bounded
    by any one host's address space per RFC 7233). The doc'd invariant (`data.len == total`
    used to `resolve()` the ranges) is what makes the cast safe — `resolve` clamps every
    range to `total`, and `data` is an actual in-memory slice, so `r.end` can never exceed
    `data.len - 1`. `writeBody` also gained a `std.debug.assert(r.end < data.len)` ahead of
    the cast as a guard against a caller passing mismatched `data`/`ranges`.
  - `h2_server.zig`: `FrameWatcher.data_bytes` and the `StagedReader`/`awaitAtLeast` plumbing
    around it narrowed from `atomic.Value(u64)`/`u64` to `atomic.Value(usize)`/`usize`. Both
    are private test-harness types tallying bytes already sitting in an in-memory
    `ArrayList`, so `usize` is the *correct* width, not just a target-compatible one; this
    also sidesteps wasm32-baseline's lack of 64-bit atomic load/RMW support.
  Verified: `zig build portable-http` no longer reports any `modules/http/src/*` error (the
  25 that remain are `[wasi-surface]` gaps in `lockfree`/`workerpool`, both fixed by other
  work, plus `http`'s own `std.Thread.spawn`/`clock_gettime` wasi-surface findings, which a
  real-threads 32-bit target would not hit). `zig build test-http` — 433/433 pass, native,
  unchanged. Cascade check: `zig build portable-acme` and `zig build portable-staticfiles`
  both now fail only on their own `[wasi-surface]` thread-spawn/libc findings — the
  `day.day`-cascade error is gone from both, confirming the fix clears the shared blocker.
  Compile-only fixes (provably safe by a bound already in the value — modulo or an
  in-memory-slice invariant — not independently testable without a >4 GiB buffer this host
  cannot allocate): the `Server.zig`/`range.zig` `@intCast` sites. Has behavioral coverage
  from pre-existing tests (the atomic narrowing changes what the existing flow-control
  tests already assert byte-for-byte): the `h2_server.zig` `usize` narrowing.
- **2026-08-18** — **BREAKING (narrow) + additive** — three fixes from the same audit report,
  landed together: this module has the most consumers in the collection (three, two outside
  the repo), so every change was checked for "does an existing caller passing no new options
  still get the same bytes on the wire".
  **(1) `Options.server_name`/`Date` can now be suppressed through `Server`, not only through
  `serveStream`.** `StreamOptions.server_name` was always `?[]const u8` and `.now` was always
  `?Now` (null = omit), because `serveStream` is the composable codec layer meant to be driven
  with no `Server` at all — but `Server.Options.server_name` was a non-optional `[]const u8` and
  `connMain` always synthesized a non-null `Now`, so a caller going through `Server` (the entry
  point almost everyone uses) had no way to reach the header-free state the socket-free path
  always could. `Options.server_name` is now `?[]const u8` (default unchanged: `"zig-libs-http/0.1"`;
  null = omit `Server`) and `Options.emit_date: bool = true` governs `Date` the same way `false` =
  omit, matching `StreamOptions.now = null`'s effect without spending the `Now` type on a surface
  that only ever wants "the server's own clock or nothing". Pinned by three new `serveStream`
  goldens (each suppression alone, then both together) and two live-loopback `Server` tests, one
  of which asserts the socket path's suppressed head is byte-identical to the socket-free one —
  that agreement is the fix. **Source-breaking, narrowly:** any caller constructing `Options` with
  a string literal or a `[]const u8` value for `server_name` is unaffected (still coerces); a
  caller that *reads* `options.server_name` back out and treats it as non-optional (e.g. passes it
  directly where `[]const u8` is expected) stops compiling. No in-workspace consumer does this —
  verified before landing — and none sets `server_name` at all today.
  **(2) `Server.bind` no longer discards the underlying `std.Io.net` error.** `BindError` stays the
  same two-tag shape (`BadAddress`/`ListenFailed`/`Canceled` — no exhaustive `switch` breaks), but
  the real error each collapsed (`IpAddress.parse`'s `ParseError`, or `IpAddress.listen`'s
  `ListenError` such as `AddressInUse`/`AddressUnavailable`) now survives in the new
  `bindErrorName()` accessor (`@errorName`, a static string — same shape `probe.ConnectOutcome`
  uses for the same reason: `std.Io.net` reports an `anyerror` here, not an errno, so there is no
  numeric code to carry). Purely additive. Pinned by two new tests: a forced `AddressInUse` (a
  second listener on an already-bound port, no `SO_REUSEADDR`) asserts the exact tag survives; a
  forced address-parse failure asserts *a* name survives without pinning which std parse-error tag
  produced it.
  **(3) Documentation only, no code change:** `Options.max_body_bytes` defaults to 1 MiB — any route
  that streams or accepts real uploads must set it to `null` or every body over 1 MiB gets a 413
  before the handler runs, now stated in README where a new consumer meets the option, not only in
  SPEC. Its struct-level asymmetry with `h2_server.Options.max_body_bytes` (`null`) is now documented
  rather than left implicit: `connMain` forwards `Options.max_body_bytes` verbatim into
  `h2_server.Options` for an `enable_h2c` connection, so a `Server`-based consumer gets the same
  hardened default on both protocols — the null default only matters for a caller invoking
  `h2_server.serve`/`.serveStream` directly (BYO-TLS, same permissive-by-default reasoning as
  `StreamOptions.max_body_bytes`). Both defaults are unchanged; nothing was silently uncapped or
  capped as part of this. Also documented: a response over `response_buffer_size` (default 4 KiB)
  switches to chunked framing silently, which has bitten a consumer whose own minimal HTTP client
  does not decode chunked — it now sets an explicit `Content-Length` on every such reply, and the
  README says so next to the option instead of only in a SPEC bullet.
- **2026-08-13** — **BEHAVIOURAL, not source-breaking** — `Client`'s two timeout
  options now bound blocking I/O. Neither did before: `connectTimeout()` was
  `_ = c; return .none;` (the real body commented out behind a
  `TODO(zig-0.16.0)`, because `Io.Threaded` **panics** — "TODO implement
  netConnectIpPosix with timeout" — on a non-`.none` `ConnectOptions.timeout`),
  so `connect_timeout_ms` was read by nothing while being advertised and
  defaulted to 5000; and `total_timeout_ms` had exactly one enforcement site,
  `checkDeadline` at the top of the *redirect* loop, so nothing checked it
  inside the dial, the TLS handshake or any read. Measured against a peer that
  accepts and then says nothing, a request hung indefinitely (>25 s, killed) in
  Debug, ReleaseSafe and ReleaseFast alike — over TLS and over plain http, so
  not a handshake quirk — and the same held for a connect the peer never
  accepted. No option value avoided it.
  The fix does not wait for std to grow a per-read deadline; it uses the
  mechanism std already has. Each blocking phase runs on a concurrent task
  (`runBounded`), and blowing the deadline **cancels** it: `Io.Threaded`
  implements cancelation by signalling the task's thread until the in-flight
  syscall returns `EINTR`, so a blocked `readv`/`connect` unwinds with
  `error.Canceled` instead of never returning. `connect_timeout_ms` now bounds
  name resolution + `connect` (`ConnectOptions.timeout` stays `.none`
  forever — that is the field that panics); `total_timeout_ms` bounds a whole
  `request` and, from the call, an `Upload.finish`. All four scenarios now
  return `error.Timeout` at 300–301 ms against a 300 ms budget in all three
  optimize modes, pinned by four tests that each run the call under a hard
  8 s watchdog so a regression is RED rather than hung, plus a fifth that
  drives the no-concurrency fallback on an `Io` with `concurrent_limit =
  .nothing`.
  Two consequences worth naming. Response **body** reads are still unbounded
  (the caller drives them), as is an `H2Session` past its dial and *everything*
  on an `Io` with no unit of concurrency to give — all three are now stated in
  `Options`, the module doc and the README instead of being implied by a knob
  that did nothing. And cancelation had to be made visible to the client:
  `std.Io.Reader`/`Writer` collapse it into `ReadFailed`/`WriteFailed`, which
  `isStaleConnError` treats as a dead pooled connection worth retrying — the
  retry would have absorbed the one cancelation the task gets and blocked
  again, with `Future.cancel` waiting on it forever. `Conn.readFailure` /
  `writeFailure` recover `error.Canceled` from the socket reader/writer, and
  the retry site now re-checks the deadline before starting fresh work.
- **2026-08-13** — *no behaviour change* — two paths that had never been executed are
  now covered. (1) `proxy.relayFailed`'s **h2** arm (`forwardH2`, `:347`/`:350`/`:351`):
  the existing 502-instead-of-mutilated-200 test drove the h1 forward path only,
  so the second relay loop was asserted by shape alone. The new h2c integration
  test reaches it with a real `http.Server` backend — which cannot overrun the
  copy-store *byte* budget (it has the same one) but can overrun the *field
  count*, because the backend's managed `Date`/`Server`/`Content-Length` cost it
  no table slot yet arrive at the proxy as ordinary headers that do, and the
  proxy adds `Via` on top. Restoring the old `catch {}` on the h2 arm alone
  turns it red (`expected 502, found 200`) while the h1 test stays green.
  (2) `Client`'s `error.EntropyUnavailable` (`dialConn:1099`) is now driven by a
  fault-injected `Io`. Replacing `try io.randomSecure` with the `io.random` that
  line rejects reports `expected error.EntropyUnavailable, found error.TlsFailed`.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — a **failed** `declareTrailers` /
  `declareTrailer` no longer leaves the trailer half-declared. Both
  `trailer_decl_len` and `declared_trailers_len` were advanced *before* the
  `Trailer` advert was re-registered through `putHeader`, and that call can
  fail on the copy-store budget; neither error arm restored either counter.
  The consequence was not counter hygiene. `declared_trailers` **is**
  `setTrailer`'s allow-list, so after a refused declaration `declaredTrailer`
  answered *true*: the caller's retry short-circuited as "already declared"
  and never re-advertised the name, yet `setTrailer` accepted it — putting a
  trailer field on the wire with no `Trailer` header naming it (**RFC 9110
  §6.6.2**), after a call that reported failure. The stuck counter also
  committed the response to chunked framing (`end` branches on
  `declared_trailers_len` alone) and made `setHeader("Content-Length", …)`
  return `InvalidHeader`, both for a trailer that was never declared. The
  second counter had its own effect: the refused name stayed in the generated
  advert text, so it reappeared in — and inflated the byte cost of — every
  later declaration, which could then fail for a budget it was not spending.
  Both are now rewound with an `errdefer`, the same shape `setHeader`'s
  `Trailer` branch already used; the two no longer disagree about what a
  refused declaration costs. Pinned by two tests (allow-list + framing, and
  advert poisoning). No error set or signature changed.
- **2026-08-13** — **BREAKING** `ResponseWriter.reset` returns `ResetError!void` (`error{HeadersSent}`)
  instead of `void`. Callers must `try` it or handle the error; `rw.reset();`
  stops compiling. It was made public earlier today guarded only by
  `std.debug.assert(!rw.sent_head)` — **which is compiled out in ReleaseFast
  and ReleaseSmall**, i.e. a fail-open precondition on a public API in the
  modes people deploy. Measured: an A/B probe whose two arms differed only by
  the `reset()` call put **two complete response heads on one connection** in
  ReleaseFast (`HTTP/1.1 200 OK … Transfer-Encoding: chunked\r\n\r\nHTTP/1.1
  200 OK\r\nContent-Length: 2\r\n\r\nbb`), with the first, chunked body never
  terminated — a response-splitting shape reached by ordinary API misuse, not
  by hostile input. `reset` clears `ended` and sets `body = .buffering` while
  leaving `sent_head` true, so the next `end()` calls `writeHead` again. Worse,
  `setHeader` still returned `HeadersSent` throughout, so a caller checking its
  return values saw nothing wrong. Debug and ReleaseSafe panicked instead. The
  precondition is now a returned error, so it holds in every optimize mode, and
  is pinned by a test that counts status lines on the wire.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — a header or trailer rejected for
  byte exhaustion no longer keeps its name's bytes. `putHeader` and
  `setTrailer` dupe the name and *then* the value into a bump allocator that
  never rewinds, so a rejected pair permanently cost `name.len` of the copy
  store: a handler that retried with a shorter value had strictly less room
  than before it asked. Both now rewind to a mark on failure. This budget is
  what decides `proxy`'s relay-versus-502, so leaking it changed answers.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — `declareTrailers` reports a byte-budget
  exhaustion as `error.HeaderBytesExhausted` rather than flattening it into
  `error.TooManyTrailers`. `TrailerError` carries both members precisely so the
  two limits can be told apart, and `setTrailer` already kept them apart; this
  one call site collapsed them and told a caller that declared ONE trailer that
  it had declared too many. No error set changed, so no exhaustive `switch`
  breaks — only the value a caller receives.
- **2026-08-13** — `Server.header_copy_bytes` (4096) is now **public**, and pinned by value.
  It was a private `const`, which meant `cookies.max_set_cookie_bytes` could
  not import it and the documented "same size as `http`'s copy store" coupling
  was a duplicated literal maintained by a comment in each file. `cookies` now
  imports it and asserts the relation at comptime. The value itself was
  unpinned downward: measured, 4096 → **2048 left the whole http + cookies
  suite green, 451/451, exit 0** — the only test that spends the budget is
  written as `header_copy_bytes / 4` and so follows the constant wherever it
  goes. Since `proxy.relayFailed` this number decides whether a proxied
  response relays or answers 502, so it is now pinned in both directions.
  Purely an addition.
- **2026-08-13** — **BEHAVIOURAL, not breaking** (`proxy`) — a backend response header the
  proxy cannot put on its own response is no longer dropped silently. Both
  relay loops (h1 and h2) used `catch {}`, so once the writer's copied-header
  budget or its 32-field table ran out, the client received a response that
  *looked* complete while missing whatever came after the limit: the
  `Location` of a redirect, the `WWW-Authenticate` of a 401, the `Set-Cookie`
  of a login, the `Content-Encoding` of a compressed body (which the client
  then decodes as plaintext). Neither end could tell. Such a response now
  answers **502** with the body `Bad Gateway: backend response headers could
  not be relayed`, carrying `Via` so the failing hop is identifiable; the
  half-relayed header set is discarded first, so nothing the backend sent
  rides along on the 502. **What changes for a consumer:** a backend whose
  response headers exceed this proxy's limits used to yield a mutilated 200
  and now yields a 502. Everything inside the limits is byte-for-byte
  unchanged. The injected response-side `Via` is treated the same way (an
  over-long `Via` chain is a 502, not a silently omitted hop); the *request*
  side keeps omitting it, since a header the backend never sees does not
  change what the client believes.
- **2026-08-13** — **BEHAVIOURAL, not breaking** (`proxy`) — the forced early
  `ResponseWriter.end()` at the end of both forward paths is gone. It existed
  so `writeHead` read the relayed header slices before the deferred
  `res.deinit()` freed the backend head buffer they pointed into; those bytes
  are copied now. **What changes for a consumer:** the response head reaches
  the wire when the serving loop ends the response rather than inside the
  handler, so middleware wrapped *around* the proxy can still touch headers
  after it returns — which is a gain (`sessions` saves its cookie there,
  `csrf` issues its token there, and both were silently losing the write on a
  proxied response), but it is an observable change of ordering. **Two halves
  of that this entry originally left out.** First, the same window lets a
  wrapping middleware `setStatus` over the *backend's* status and `setHeader`
  over a relayed backend header; those writes were previously inert
  `HeadersSent` no-ops, so a middleware that always sets a header now silently
  overrides the origin instead of losing to it. Second, the gain is
  conditional: it holds only while the proxied body fits the response buffer.
  A larger body trips `beginStreaming` → `writeHead` inside `streamRemaining`,
  so the head goes out inside the handler exactly as before and the
  post-proxy middleware write is lost again — on precisely the large
  responses where it is least likely to be noticed.
- **2026-08-13** — `ResponseWriter.reset` is now **public**. It discards everything composed so
  far — status, header table, copied bytes, declared trailers, buffered body —
  and is legal only while nothing is on the wire. A handler that composes a
  response and only then discovers it cannot finish it (`proxy` above)
  otherwise has no way to stop the half-built answer from riding along with
  the error status that replaces it. Purely an addition.
- **2026-08-12** — Docs: `setTrailer`'s doc still claimed name and value are stored **without**
  copying and must stay valid until `end`. They have been copied since the
  fix below; the doc was describing the defect it repaired.
- **2026-08-12** — **BREAKING** `Client.Error` gains `error.EntropyUnavailable`. An exhaustive
  `switch` over it stops compiling until it handles the new case; a `catch |e|
  switch (e) { ... else => }` is unaffected, and every in-repo consumer
  (`proxy.statusForBackendError`, `llmclient.mapHttpError`, `h2_upstream`)
  already uses `else`. It exists because `dialConn` now draws TLS key material
  with `io.randomSecure` instead of `io.random`. `std.Io.random` is a CSPRNG
  whose contract permits a silent fallback to a weaker seed
  (`std/Io.zig:2462`), and the default `Io.Threaded` takes it — seeding from
  pid + wall clock + an ASLR pointer. This is the one place in the library
  where that mattered most: the caller hands over `io` because they want
  **sockets**, and the ClientHello random and key share for every HTTPS
  request were being drawn from that same capability with no signal at the
  call site. Now it fails closed instead.
- **2026-08-12** — **BREAKING** `SetHeaderError` and `TrailerError` gain
  `error.HeaderBytesExhausted`. An exhaustive `switch` over either set stops
  compiling until it handles the new case; a `catch |e| switch (e) { ... else
  => }` is unaffected. It exists because header and trailer name/value bytes
  are now COPIED into the response writer rather than borrowed from the
  caller, which buys a byte budget the borrowing version did not have.
- **2026-08-12** — Header and trailer bytes are copied at `setHeader` / `setTrailer` /
  `addSetCookie` time. **This fixes a use-after-scope**: `writeHead` runs
  inside `end()`, which both servers call after the handler returns, so a
  handler that formatted a value into a stack buffer had those bytes read
  after its frame was gone. The old contract ("name/value slices must outlive
  the response") was documented and unmeetable. Callers that worked around it
  with `threadlocal` buffers, or by forcing an early `end()`, no longer need
  to. Debug and ReleaseFast passed the defect by luck; only ReleaseSafe
  exposed it.

- **2026-07-29** — Response **trailers** — the write side, which was previously documented
  as out of scope. `ResponseWriter.declareTrailers` + `setTrailer` emit a
  trailer section after the terminating chunk on HTTP/1.1 (RFC 9112
  §7.1.2) and as a trailing HEADERS frame carrying END_STREAM on HTTP/2
  (RFC 9113 §8.1 — the last DATA frame therefore does not carry it), from
  the same handler code. Declaring trailers commits the response to
  chunked framing, so `Trailer` and `Content-Length` can never coexist,
  and every framing that cannot carry a trailer section (HTTP/1.0 peer,
  declared `Content-Length`, HEAD/1xx/204/304) is a typed error at set
  time rather than silently dropped output. Field policy is **deny-list ∧
  allow-list**: the RFC 9110 §6.5.1 forbidden set (framing, routing,
  request modifiers, auth, response control data, payload processing,
  plus connection-specific fields, `Cookie`/`Set-Cookie` and any `:`
  pseudo-header) is refused unconditionally, *and* a field must have been
  advertised in `Trailer` first — unconstrained trailers are a
  request-smuggling and cache-poisoning vector because intermediaries
  handle them inconsistently. The h2 **read** gaps closed with it: request
  trailers now reach the handler through the same `Request.trailer`
  surface as h1, and `h2_client.Response.trailers`/`.trailer(name)`
  surfaces response trailers (a trailer block containing pseudo-headers is
  dropped whole, §8.1). Anchored against **live curl 8.18 / nghttp2 1.68**
  on both protocols (`src/curl_interop.zig`), not only against our own
  client.
- **2026-07-19** — Security audit: hardened against HTTP request-smuggling (part of the
  collection-wide CRIT/HIGH audit; the root changelog records no further
  detail than this).
