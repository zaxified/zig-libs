# icmp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
