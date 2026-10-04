# crc32c

**CRC-32C (Castagnoli)** at hardware speed: the SSE4.2 `crc32` instruction
on x86-64 and the ARMv8 `crc32c*` instructions on arm64, three streams
interleaved, with a slicing-by-8 fallback everywhere else. The same value as
`std.hash.crc.Crc32Iscsi`, 15–45× faster (below).

- **Status:** gap — std has CRC-32C only as a bytewise table (~0.45 GB/s),
  which made it the bottleneck of `seglog`'s reads.
- **Model after:** Go `hash/crc32` (Castagnoli with SSE4.2, three-way) and
  zlib's `crc32_combine`; the three-stream construction is Intel's "Fast CRC
  Computation for iSCSI Polynomial Using CRC32 Instruction" (2011).
- **Platform:** any (x86-64 and arm64 get the instructions, chosen at run
  time). **Role:** util. **Concurrency:** reentrant. **Allocation:** none.

```zig
const crc32c = @import("crc32c");

const c = crc32c.hash(bytes);                  // one shot
const c2 = crc32c.extend(c, more);             // == hash(bytes ++ more)
const c3 = crc32c.combine(c, crc32c.hash(more), more.len); // same, without the bytes

var s = crc32c.Crc32c.init();                  // std.hash.crc's shape
s.update(part1);
s.update(part2);
_ = s.final();

_ = crc32c.backend();                          // .sse42 / .armv8 / .table
```

**Which instruction runs is decided at run time** (CPUID on x86-64,
`AT_HWCAP` on Linux arm64), once, unless the build target already guarantees
it — so a binary built for baseline x86-64 still gets SSE4.2 on a CPU that
has it. The instructions are inline assembly, which Zig 0.16 emits whatever
the target's feature set.

## Speed

GB/s, best of 5, ReleaseFast, one core of the development notebook
(2026-09-27, x86-64 with SSE4.2; a loaded machine, so the ratios are the point):

| bytes | std `Crc32Iscsi` | `.table` | hardware |
|---:|---:|---:|---:|
| 64 | 0.49 | 2.10 | 7.1 |
| 180 | 0.47 | 1.92 | 7.1 |
| 4 KiB | 0.45 | 1.93 | 17.5 |
| 64 KiB | 0.45 | 1.94 | 20.4 |
| 1 MiB | 0.45 | 1.92 | 20.6 |

A build for baseline x86-64 measured the same within noise (6.7–20.0).

Provenance: original work of the zig-libs authors (MIT). The polynomial and
check values are public (RFC 3720, the reveng CRC catalogue); the
three-stream split and the GF(2) multiply follow published descriptions
(Intel's white paper, zlib's documented `crc32_combine` algorithm); no
third-party source was translated, so no NOTICE entry. The `combine` test vectors
(`src/kat_vectors.zig`) are captured from Go's `hash/crc32` run as a black-box
oracle by `tools/gen_kat.go`; nothing of Go's source was consulted or copied.
