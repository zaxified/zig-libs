# icmp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
