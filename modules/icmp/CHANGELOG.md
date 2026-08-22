# icmp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
