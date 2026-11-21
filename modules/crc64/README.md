# crc64

**CRC-64/XZ (ECMA-182 polynomial, reflected; the `.xz` CRC64 check)** at hardware speed:
PCLMULQDQ carry-less folding on x86-64 with a slicing-by-8 fallback everywhere else. The
same value as `std.hash.crc.@"CRC-64/XZ"`, which is a bytewise table.

- **Status:** gap — std has CRC-64 only as a bytewise table (about 5 % of an `lzma` decode).
- **Model after:** liblzma's `lzma_crc64` (`check/crc64_fast.c`, `crc_x86_clmul.h`).
- **Platform:** any (x86-64 gets the instruction, chosen at run time). **Role:** util.
  **Concurrency:** reentrant. **Allocation:** none.

```zig
const crc64 = @import("crc64");

const c = crc64.Crc64.hash(bytes);        // == std.hash.crc.@"CRC-64/XZ".hash(bytes)
const c2 = crc64.extend(c, more);         // == hash(bytes ++ more), lzma_crc64(more, len, c)

var s = crc64.Crc64.init();               // std's streaming shape
s.update(part1);
s.update(part2);
_ = s.final();
```

Inputs under 16 bytes and the tail past the last 16-byte multiple use the table.

Provenance: the polynomial and the check value (0x995DC9BBDF1939FA for "123456789") are public (reveng CRC
catalogue). The folding kernel and its constants are a translation of liblzma's (0BSD, see `NOTICE`).
The frozen test values were computed by liblzma as a black box (`tools/gen_kat.py`).
