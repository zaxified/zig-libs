# framing — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-10** — **NO CONSUMER-VISIBLE CHANGE** (Zig 0.17.1 migration): `toU64` is `std.math.cast(u64, x)` again instead of a range test plus bit reinterpretation, which avoided the Zig 0.17.0 `trunc nsw` miscompile (ziglang/zig#37131, fixed in 0.17.1; `build.zig` now refuses older compilers). The hostile-length-field test stays as its regression guard.
- **2026-11-08** — **NO CONSUMER-VISIBLE CHANGE:** `jsonDepthWithin` is now a thin wrapper over `jsontext.depthWithin` (same results); new dependency `jsontext`.
- **2026-11-03** — **BEHAVIOURAL, not breaking:** `writeFrame`/`writeFrameWithHeader` return the new `error.SkipNotWritable` for a `Prefix.skip` other than null or the whole head (such a frame would not read back); length arithmetic no longer casts signed to a narrower unsigned (Zig #37131 guard); the fuzz model now also checks what the writer emits.
- **2026-11-03** — `Prefix` gained `offset`, `adjustment` and `skip` (tokio `length_field_offset`/`length_adjustment`/`num_skip`) and `Width` the odd sizes `u24`/`u40`/`u48`/`u56` (tokio's full 1-8 byte range); `writeFrameWithHeader` writes the offset bytes. Defaults are unchanged, so existing wire formats and call sites keep working; a nonzero `offset` makes `writeFrame` return `error.HeaderRequired`. Checked against tokio-util 0.7.19 (`tools/oracle`, `tools/diff.zig`).
- **2026-10-30** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the § GS sweep: 9/10 + 1 eq (Decoder `+|` eq on 64-bit); new test: a 16 KiB frame is one exact allocation (sweep audit GS-FR-1).
- **2026-10-30** — **CONSUMER-VISIBLE:** no-panic sweep + blind review (§ GS). `readFrameAlloc` grows its buffer by the bytes actually read above 16 KiB instead of allocating the announced length up front (a stalling peer cost the whole announced frame); `EnvelopeCodec.parse` now copies every string (`alloc_always`) — escape-free strings used to alias the input bytes and dangled once the frame buffer was reused or freed; `Decoder.feed` limit arithmetic saturates (32-bit). Docs: EnvelopeCodec memory scales with element count × element size; EndOfStream covers a clean close and a truncated frame; a failed write leaves a partial frame. Tests: `src/sweep_test.zig`.
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

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
