# crc32

**CRC-32 (IEEE 802.3 / gzip / zlib / PNG)** at hardware speed: PCLMULQDQ
carry-less folding on x86-64 and the ARMv8 `crc32x` instructions on arm64,
with a slicing-by-8 fallback everywhere else. The same value as
`std.hash.Crc32` — a drop-in for it — 3.5× faster at 16 bytes, 15× at 64, 50× from 1 KiB (below).

- **Status:** gap — std has CRC-32 only as a bytewise table (~0.45 GB/s),
  which cost `http`'s gzip ~14 % of its deflate time at 16 KiB.
- **Model after:** zlib's `crc32` / `crc32_combine` and Linux's
  `crc32-pclmul`; the folding is Intel's "Fast CRC Computation for Generic
  Polynomials Using PCLMULQDQ Instruction" (2009).
- **Platform:** any (x86-64 and arm64 get the instructions, chosen at run
  time). **Role:** util. **Concurrency:** reentrant. **Allocation:** none.

```zig
const crc32 = @import("crc32");

const c = crc32.hash(bytes);                   // == std.hash.Crc32.hash(bytes)
const c2 = crc32.extend(c, more);              // == hash(bytes ++ more), zlib's crc32(c, …)
const c3 = crc32.combine(c, crc32.hash(more), more.len); // same, without the bytes

var s = crc32.Crc32.init();                    // std.hash.Crc32's shape
s.update(part1);
s.update(part2);
_ = s.final();

_ = crc32.backend();                           // .pclmul / .armv8 / .table
```

**Which instruction runs is decided at run time** (CPUID on x86-64,
`AT_HWCAP` on Linux arm64), once, unless the build target already guarantees
it — so a binary built for baseline x86-64 still folds with PCLMULQDQ on a
CPU that has it. The instructions are inline assembly, which Zig 0.16 emits
whatever the target's feature set. Inputs under 32 bytes use the table,
which is as fast there.

## Speed

MB/s, best of 7, ReleaseFast, pinned to one core of the development notebook
(2026-09-28, i7-7920HQ: SSE4.2, PCLMULQDQ, AVX2; a loaded machine, so the
ratios are the point):

| bytes | std `Crc32` | `.table` | `.pclmul` |
|---:|---:|---:|---:|
| 16 | 836 | 2 959 | 2 928 (table) |
| 32 | 639 | 2 887 | 6 172 |
| 64 | 525 | 2 614 | 8 213 |
| 180 | 460 | 1 899 | 6 960 |
| 1 KiB | 447 | 1 899 | 22 909 |
| 16 KiB | 450 | 1 915 | 24 679 |
| 1 MiB | 451 | 1 918 | 22 145 |

A build for baseline x86-64 (run-time detection) measured the same within
noise (7.9 GB/s at 64 B, 22.9 at 1 KiB, 22.7 at 16 KiB). The arm64 path has
been verified under `qemu-aarch64` only, which says nothing about its speed.

Provenance: original work of the zig-libs authors (MIT). The polynomial and
check value are public (ISO 3309, RFC 1952, the reveng CRC catalogue); the
folding and the GF(2) multiply follow published descriptions (Intel's white
paper, zlib's documented `crc32_combine` algorithm) and every constant is
derived in the source; no third-party source was translated, so no NOTICE
entry. The `combine` test vectors
(`src/kat_vectors.zig`) are captured from Go's `hash/crc32` run as a black-box
oracle by `tools/gen_kat.go`; nothing of Go's source was consulted or copied.
