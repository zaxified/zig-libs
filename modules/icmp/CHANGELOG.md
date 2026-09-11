# icmp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-11** — **A1 fix campaign round 2: six findings closed. BEHAVIOURAL
  and API changes — see below.**

  - **F1/F12-m30 (HIGH, API change): `Socket.sendMany` guarded two
    fixed-size stack arrays with `std.debug.assert`.** `ReleaseFast`/
    `ReleaseSmall` compile asserts out; measured 2026-09-05 with 64 packets
    against `batch_max = 16`: Debug/ReleaseSafe panicked (SIGABRT),
    ReleaseFast wrote past both arrays (SIGSEGV, no diagnostic). Same class
    this module already closed twice for `recvBatch` and
    `writeEchoRequest`. `sendMany` now returns `error{TooManyPackets}!usize`
    instead of asserting. **Breaking**: callers of `sendMany` now handle an
    error instead of relying on the precondition. The only caller in this
    repo, `Pinger.dispatchDue`, never builds a batch bigger than
    `batch_max` (its own collect loop bounds it), so this is a no-op there
    in practice — updated to `try` the call.
  - **F3/F10 (HIGH, BEHAVIOURAL): a sustained flood on the socket kept
    `step()` from ever returning.** `drainReplies`'s per-family loop had no
    cap on `recvBatch` calls; under continuous inbound traffic it never hit
    the "short batch" exit. Measured 2026-09-05 (`perf flood2`, six
    concurrent flooders): a 200ms-budget `run()` took 1500.9-9046.5ms
    (7.5x-45x) across six runs; a quiet run and post-flood recovery both
    held 200.7-200.9ms. Reproduced far more severely in-tree with a
    4-thread `sendmmsg` flood: `step()` spun at ~494% CPU and did not
    return within a 900s hard timeout. Fixed with a bounded per-`step()`
    packet budget (`max_batches_per_drain = 64` batches, i.e. 1024 packets
    per family) — nothing is dropped, only deferred to the next `step()`
    call, since the kernel socket buffer holds the backlog and the socket
    stays reported-readable. **F10** (the retry chain's total worst-case
    duration, `timeout_ns * (backoff_factor^(retries+1) - 1) /
    (backoff_factor - 1)`, e.g. 4067ms for the *default* `Config{}`) is a
    DIFFERENT mechanism — entirely determined by caller-chosen `retries`/
    `backoff_factor`, not by anything an adversary or environment can
    inflate — so it is closed by documenting the worst-case formula on
    `Config.retries` rather than by capping a value the caller set on
    purpose.
  - **F5 (MED, BEHAVIOURAL): `Stats.icmp_errors` was structurally always 0
    on the default (DGRAM) socket path.** The kernel never puts an ICMP
    error about a ping DGRAM socket's own probe on its normal receive
    queue — only on the socket error queue, and only once `IP_RECVERR`/
    `IPV6_RECVERR` is set (verified live: a forged Time Exceeded produced
    nothing on a normal `recvmsg` but appeared on `MSG_ERRQUEUE`
    immediately once the option was set, complete with the quoted echo
    header as payload and the quoted destination as the reported address).
    `Socket.open` now always sets the option, and a new `Socket.recvErr`
    plus `Pinger.drainErrQueue` correlate error-queue entries by quoted
    ident/seq (and, when `check_source` is on, quoted destination) exactly
    like the RAW path's `.icmp_error` branch already did. Fixes `pathmtu`'s
    dependency on this stat's hint branch on its default (`.auto`) socket
    mode as a side effect.
  - **F6 (MED, BEHAVIOURAL): a RAW socket's echo identifier was the process
    id.** `@intCast(linux.getpid() & 0xffff)` is this module's own
    correlation token on the RAW path (the kernel never uses it to demux
    raw traffic), not a secret — but a PID is about as guessable as a
    token gets (measured: 299/299 consecutive idents on a busy host differ
    from a neighboring process's by exactly 1). Now drawn from the kernel
    CSPRNG (`getrandom(2)`, since `std.crypto.random` does not exist in
    0.16), with the old PID-derived value only as a fallback if the
    syscall itself is refused. The DGRAM path is unaffected — the kernel
    picks that identifier, not this module.
  - **F8 (MED, BEHAVIOURAL): `check_source` defaulted to `false`.**
    `ident`+`seq` are the only correlation key without it, and neither is a
    secret (`seq` is a plain per-target counter by design; even a random
    `ident`, F6 above, is just 16 bits with no rate limit on wrong
    guesses). Measured live 2026-09-05: with the guard off, a single reply
    forged with a neighboring target's ident/seq marked that OTHER target
    alive — a monitoring tool watching many targets can least afford one
    spoofable host vouching for every other host in the same run. Default
    changed to `true`; set `false` explicitly to restore the old
    fping-compatible default.

  `scripts/modtest icmp`: 67/70 (3 skip) without privilege, **70/70** under
  `unshare --user --map-root-user --net` (Debug/ReleaseSafe/ReleaseFast).
  Consumers: `scripts/modtest traceroute` 33/33 under `unshare` (32/33, 1
  skip, without), `scripts/modtest pathmtu` 35/35 either way — neither
  needed a source change, both only rebuilt against `Socket.zig`.

- **2026-09-10 (2)** — A1 fix campaign, F12 (LOW), mutation-table coverage —
  16 of the 22 surviving mutations now killed (17 new tests: 7 in `echo.zig`,
  1 in `Socket.zig`, 9 in `pinger.zig`), no behavior change:
  - **echo.zig** (m8, m15, m16, m18, m26, m27): each of the length-boundary
    guards in `parseV4`/`parseV6`/`writeEchoRequest` is protected by a
    DIFFERENT, more permissive check nearby, so a mutation on the specific
    line the audit named left the suite green through the other check —
    each new test is built to be observable ONLY through its named guard
    (typically: the shortest input that makes the *next* line read/slice
    past the buffer once the named guard is gone). Verified RED: all 6
    crash under the exact `mut/mutate.py` mutation text; GREEN on revert.
  - **Socket.zig** (m25): `parseControl`'s cmsg-list walk now has a test
    with a cmsg claiming a `len` far past the control buffer. m28
    (`parseSrc`'s `namelen < 2` check) is an EQUIVALENT MUTANT given the
    current code shape — every downstream branch already requires
    `namelen >= @sizeOf(sockaddr.in)` (16) or `>= @sizeOf(sockaddr.in6)`
    (28), both of which imply `namelen >= 2`, so deleting the explicit
    check changes no observable output for any input. Not testable because
    there is nothing to distinguish, not because of a testing gap.
  - **pinger.zig** (m2/m3/m31, m4/m32, m5, m6, m17, m19, m20, m23, m24):
    correlation (RAW/error ident compared bit-by-bit in a 16-position
    flip loop — kills "compare N bits" for any N and any bit position;
    address-family cross-check; `check_source` actually enforced on the
    `.echo_reply` arm, not just the `.icmp_error` arm F2 already covered;
    duplicate-reply detection) and scheduling (`max_inflight` cap,
    global pacing gap, stale-timeout-slot ownership, future timeouts not
    firing early). Verified RED: all 9 fail/crash under the exact mutation
    text (`if (false) ...` / `if (false and ...)`, matching
    `mut/mutate.py`'s shapes); GREEN on revert, no collateral failures in
    the other 57 tests.
  - **m30** (`sendMany`'s `std.debug.assert`) is F1 territory (a user
    decision item this session was told not to touch) — left untouched,
    still open.
  - `scripts/modtest icmp`: 66/66, Debug and ReleaseSafe. Consumers
    unaffected (no production code touched): `scripts/modtest traceroute`
    32/33 (1 skip), `scripts/modtest pathmtu` 35/35.

- **2026-09-10** — **NO CODE CHANGE.** A1 fix campaign, F14 (LOW), documentation
  only. `addTarget`/`addTargetAddr`/`addTargetIp` validate nothing about the
  destination (multicast/broadcast/loopback/unspecified are all accepted and
  probed like any other target); the kernel itself already blocks the classic
  smurf-amplification shape (no `SO_BROADCAST`), so this was left LOW rather
  than fixed in code — but `SPEC.md`'s threat model had not one sentence about
  it. Documented, including that `netaddr` (an existing dependency) already
  exports the predicates (`isLoopback`/`isPrivate`/`isMulticast`/
  `isLinkLocalUnicast`/`isUnspecified`) a caller can filter its own target list
  with before calling `addTarget`. Doc-only, `scripts/modtest icmp`: 50/50,
  unchanged.

- **2026-09-10** — **A1 fix campaign: five findings closed.**

  - **F9 (HIGH-adjacent correctness): `checksum()` overflowed past 131074
    bytes.** `sum` accumulated in `u32`; the largest possible per-16-bit-word
    contribution (`0xffff`) times enough words overflows it at 65537 words —
    a panic in Debug/ReleaseSafe, a silently wrong result in ReleaseFast
    (measured: `-> 0x1`). `checksum` is public API with no documented length
    bound. Widened the accumulator to `u64`.
  - **F2 (HIGH): the quoted IP header inside an ICMP error was parsed, used
    to locate the quoted echo/timestamp header, and then discarded.**
    `Reply.icmp_error` gained three additive fields — `quoted_src`,
    `quoted_dst`, `quoted_proto` — so a caller can verify a quoted error
    actually describes a probe of theirs, not just that `orig_ident`/
    `orig_seq` happened to match. `check_source` (when enabled) now also
    validates the quoted destination on the `.icmp_error` path in this
    module's own `Pinger`, closing the same gap the audit measured live
    (`te_wrongdst_cs_raw`: a forged Time Exceeded quoting the wrong
    destination still counted with `check_source = true`). This closes the
    `traceroute` module's own audit finding F3 (HIGH), which was blocked on
    this field not existing.
  - **F7 (MED): the receive-side ICMP checksum was never verified.**
    `parseV4` now rejects a packet whose checksum does not verify before
    looking at anything else in it (measured live: a forged reply with a
    deliberately wrong checksum was accepted on the RAW socket path).
    IPv6 is unaffected — this module never computes the IPv6 checksum
    itself (it needs the pseudo-header, which only the kernel has), so
    there is no in-module reference to verify a received one against.
    Closes `traceroute`'s audit finding F4 (MED) at the source, and (as a
    side effect of `parseV4` now rejecting the seven-line-quote fixture
    the audit used) confirms Linux does deliver a checksum-invalid ICMP
    error to a raw socket — the question `traceroute`'s own F4 had left
    open.
  - **F4 (HIGH): four `Config` fields turned into UB in ReleaseFast** —
    `retries = 65535` overflowed `1 + retries` in `u16` arithmetic (Debug/
    ReleaseSafe panicked; ReleaseFast never returned); `backoff_factor`
    (huge, negative, or NaN) made `@intFromFloat` UB in `backoff()` (same
    panic/hang split); `max_inflight >= seqmap.capacity` was an
    `std.debug.assert`, the same fail-open-in-release pattern as the
    `recvBatch`/`writeEchoRequest` fixes below. All three are hardened
    directly (an equivalent, overflow-free retry comparison; `backoff()`
    clamps non-finite/negative/overflowing products instead of converting
    them; the assert is now `error.MaxInflightTooLarge`), rather than adding
    a separate `Config.validate()` — no public signature changed.
  - **F13 (LOW): `sourceMatches(.none, _)` returned `true`** — "cannot
    verify" read as "verified", the one fail-open reading of a guard that
    is fail-closed everywhere else. Not reachable on Linux today (`recvmsg`/
    `recvmmsg` always fill `msg_name`), fixed defensively.

  Left open (see A1 audit record `icmp.md` for detail): F1 (`sendMany`'s
  remaining `std.debug.assert`, same class as the two fixed 2026-08-22 below
  — breaking API change, needs a decision); F3/F10 (no bound on a `step()`'s
  packet-drain loop or a target's total retry-chain wall time); F5
  (`Stats.icmp_errors` is structurally always 0 on the default DGRAM path —
  needs `IP_RECVERR`, or the README's claim needs correcting); F6 (echo
  ident is a per-namespace counter on the DGRAM path, not random); F8
  (`check_source` off by default — a design decision, not a bug; its guard
  now has direct tests); F15 (documented only: a quoted `timestamp_request`
  is accepted by design for `Pinger`'s own use, and `parseV4` must not be
  called with non-ICMPv4 bytes — the ICMPv4/ICMPv6 type spaces collide).

- **2026-09-07** — **`fuzzParsers` handed all three parsers an EMPTY packet on
  every input it ever ran, and had no corpus.**

  It opened with `smith.bytes(&buf)` followed by
  `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` consumes `min(buf.len, in.len)`
  octets and a ranged draw then reads eight *more* as a little-endian u64, returning
  the range minimum when fewer remain — so the drawn length was 0 for every input a
  seed can carry, and `parseV4`/`parseV6` were handed `buf[0..0]`, which they reject
  on their first line. Nothing past `if (buf.len < echo_header_len)` had ever
  executed: not the quoted-header walk (`qihl`, the arithmetic that indexes into an
  attacker-supplied IP header inside an ICMP error), not the SOCK_RAW strip path, not
  the timestamp-reply branch. The harness also discarded all three results, so even
  had it reached them it asserted nothing.

  One `smith.slice(&buf)` draw, a 17-entry hex corpus (the real loopback captures,
  the constructed quoted-error frames from the value tests, and the exact
  quoted-header boundary — 27 octets of quote rejected, 28 accepted), and two
  assertions the harness now makes: the strip path must agree with the plain path
  over what follows a minimum-length IPv4 header, and an `.icmp_error` result must
  not come back for a packet too short to hold the quote it reports.

  Measured 2026-09-07, before → after: **0 of 17 seeds non-empty → 16 of 17** (the
  empty datagram is a seed on purpose), and **0 packets classified → 8**: 3 v4 echo
  replies, 3 v4 quoted errors, 1 v6 echo reply, 1 v6 quoted error. The classified
  counts are the discriminating ones — `.ignored` is what both a rejected packet and
  an *unread* one come back as, so there is no error return here for a guard to
  count.

- **2026-08-22** — **Breaking:** `Socket.recvBatch` returns
  `error{SlabTooSmall}![]const RecvInfo` instead of `[]const RecvInfo`, and
  `pinger.RunError` gained `RecvSlabTooSmall`. The `batch_max * slot_size` slab
  requirement was an `std.debug.assert`, so in ReleaseFast/ReleaseSmall a short
  slab let `recvmmsg` write past its end. Both operands are runtime values, so
  unlike the fixed-size writers below the requirement cannot move into the type.
  `Pinger` sizes its own slab and never returns the new error.

- **2026-08-22** — **Breaking:** `echo.writeTimestampRequest` takes
  `*[timestamp_msg_len]u8` instead of `[]u8`, and `echo.writeEchoRequest` returns
  `error{BufferTooSmall}!void` instead of `void`. Both guarded their buffer with
  `std.debug.assert`, which compiles out of ReleaseFast and ReleaseSmall, so a short
  buffer was a silent overwrite in exactly the modes that ship. The timestamp message is
  a fixed size, so its requirement moved into the type; an echo request is a header plus
  a caller-chosen payload, so its size cannot be expressed there and is reported instead.
  `Pinger.RunError` gains `SendBufferTooSmall`, which `init` sizes the send slab to make
  unreachable — propagated rather than swallowed so no caller decides the check is
  unnecessary and puts the fail-open guard back.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against RFC
  1071 for the checksum algorithm; the wire-format goldens themselves are self-authored.
- **2026-07-04** — New module: ICMP echo (ping) engine — v4/v6 codec, batched socket,
  pacing.
