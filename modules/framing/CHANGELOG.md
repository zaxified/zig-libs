# framing — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — ADDED (both survey 2026-09-30 gaps), no breaking change: `Limits.prefix`
  (`Prefix{ width: u8|u16|u32|u64|varint, endian, includes_prefix }`, default = the original
  u32-LE) honoured by `writeFrame`/`readFrame`/`readFrameAlloc`; `Decoder` — incremental,
  non-blocking (`feed` / `next`), oversize refused at the prefix, sticky errors, bounded buffer
  (`error.NotDrained`). New error `BadLength` for a malformed length field (only reachable with a
  non-default prefix or a self-counting one). Wire bytes checked by hand (protobuf's `300 = ac 02`,
  network-order u16/u32/u64); a 2000-stream deterministic driver shows `Decoder` and `readFrame`
  agree on every format and garbage never panics. Mutation 2026-10-04: 24 mutants, 22 killed
  (one by a hang), 2 equivalent; 1 test added.

- **2026-09-07** — **Tests:** `fuzzReadFrame` never decoded a length prefix.
  It filled a buffer with `smith.bytes` and then drew the stream length with
  `valueRangeAtMost(u16, 0, buf.len)`; a ranged `Smith` draw reads eight octets
  as a little-endian u64 and returns the range MINIMUM when fewer remain, so
  the length was 0 on every input a corpus can carry and `readFrame` failed
  inside `takeArray(4)` before reaching the 4-byte header this module exists to
  bound-check. With no corpus, that empty stream was the only input it ever
  ran. Now one `smith.slice(&buf)` draw, a 12-seed corpus laddering the
  announced `u32` across `out.len` and `default_max_frame`, and `readFrameAlloc`
  fed the same bytes (it bounds the same attacker-chosen length without a
  caller buffer to clamp it). Measured: 0 frames read, 0 payload octets and 0
  `FrameTooLarge` refusals before; 5 / 138 / 4 after. The corpus guard pins the
  payload octets rather than a success count, because the zero-length frame is
  a legal frame here and "something was accepted" would have read healthy on a
  harness that moved no payload at all.

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this).
- **2026-07-09** — New module: Length-prefixed stream framing (`writeFrame`/`readFrame`)
  + a generic JSON tagged-union envelope codec.
