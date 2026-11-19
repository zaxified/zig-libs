# `bzip2` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** test fix: the StreamWriter vector/splat test passed a `@constCast` comptime slice array to `writeVecAll`/`writeSplatAll`, which advance the slices in place; ReleaseFast put it in read-only memory and the test crashed (SEGV). The arrays are now mutable locals.
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** whole-module mutation run (820 schemata mutants over every non-test line: 699 killed, 109 equivalent, 12 unobservable, none in a bounds or security check) and the tests it asked for: hand-built decoder streams (each magic letter alone, zero selector count, selector value range, groups against selectors, 20-bit codes in both symbol loops, a run after a symbol overflowing the block, 1..3 equal bytes at a block end), the block buffer's growth and cap, `total_out` at the cap, `decompressStream` length / flush / unbuffered writer, table counts at 200/600/1200/2400 symbols, the 17-bit code limit, a full output buffer at `bsFinish`, failing-allocator sweeps, `compressInto` and `StreamWriter` write paths, pinned halving and B4 counters, and libbzip2 goldens for ties between equal rotations (11 `wf-t*` shapes and 240 repeated-unit inputs, work factor 30). SPEC "Audit 2026-11-19" lists the groups; the card's mutation entry is now whole-module.
- **2026-11-18** — **Behaviour change (encoder, adversarial input only):** the fallback block sort's quicksort stops at a work bound (`blocksort.fallback_work_factor` x n x (log2 n + 1) per call) and sorts the rest with an O(n log n) sort. A 900 KiB block crafted against libbzip2's pivot choice took 13.8 s to sort, now 153 ms; `compress` of a 787 KiB crafted input 6.9 s, now 206 ms. Below the bound — every shape of the golden corpus, random, sorted and shuffled data, at most 1/7 of it measured — the output is byte-identical to libbzip2 1.0.8 as before; above it only the origin pointer of a periodic block can differ (the stream still decodes to the same data).
- **2026-11-15** — **NO CONSUMER-VISIBLE CHANGE:** documentation wording (consumer project names removed).
- **2026-11-10** — **NO CONSUMER-VISIBLE CHANGE** (Zig 0.17.1 migration): the coding-table length narrowing is a direct `@intCast(curr)` again; the detour through u32 guarded against the Zig 0.17.0 `trunc nsw` miscompile (ziglang/zig#37131, fixed in 0.17.1; `build.zig` now refuses older compilers).
- **2026-10-30** — **BEHAVIOURAL, not breaking:** no-panic sweep + blind review (§ GU). `Options.max_output` defaults to 256 MiB (`decoder_default_max_output`, a decompression-bomb guard like brotli's; `null` = unbounded, an explicit opt-out) — a stream that decodes to more now ends in `error.OutputTooLarge`. Fixes: `StreamWriter.finish` is idempotent and its error path no longer `@errorCast`s an out-of-set error (a second `finish` was an invalid cast = UB in ReleaseFast); `Encoder` latches its first error (a retry no longer re-emits a header/CRC); `Decoder.read` with an empty `dest` returns 0; a zero-capacity `in` buffer works (read via `readVec`, 64 consecutive empty reads = `ReadFailed`); the stream counter and `compressBound` saturate. Tests: `src/sweep_test.zig`.
- **2026-10-23** — **Fix (performance):** `DecompressReader` refills its buffer on small reads. Zig 0.17's `defaultReadVec` streams straight into the caller's slice once the buffer has been filled to its end, so every later small `readSlice*` re-entered the decoder for that many octets. Regression test with a negative control. No API change.

- **2026-10-20** — **NO CONSUMER-VISIBLE CHANGE:** tests for the survivors of the mutation run. Hand-built streams (a small bit writer in `decoder_test.zig`) pin the decoder's validation: level digit, table count 0/1, selector lists past 18002, code lengths 0/20/21, origin pointer judged before the body, RUNA/RUNB limit 2^21, level-1 block fill, first block-magic bytes, a randomised block past the 512-entry flip table; 20 new libbzip2 goldens (`tc-*` table-count edges, `wf-*` periodic sort-path blocks at work factors 1/30/100; `zig build interop-bzip2 -- --capture`).
- **2026-10-20** — **NO CONSUMER-VISIBLE CHANGE:** mutation run (schemata, 94 mutants: 56 killed, 9 equivalent); the surviving decoder-validation and encoder-threshold mutants are open test gaps (SPEC Backlog).
- **2026-10-20** — Independent review (no HIGH/MEDIUM): the decoder now stays failed after its first error
  (`Decoder.failed`; a retry used to re-enter the bit reader's EOF padding), `Encoder.finish`/`write` after
  `finish` return `error.AlreadyFinished` (was an assert, a second trailer in ReleaseFast), the code-length
  narrowing goes through u32 (#37131-proof), the table-memory figure corrected (~45 KB).
- **2026-10-20** — New module: bzip2 (.bz2, and the raw stream ZIP method 12 carries). A
  compressor for levels 1..9 that emits, byte for byte, what libbzip2 1.0.8 emits (checked
  against libbzip2 over 36 input shapes, every level, work factors 1/30/100 and CLI-style
  chunking; `tools/interop.zig`), `compress` / `compressInto` / `StreamWriter`; a streaming
  decompressor (`decompress`, `decompressStream`, `DecompressReader`) for concatenated
  streams with block and stream CRCs, randomised blocks, typed errors and a `max_output` bomb
  cap, memory bounded by one block.
