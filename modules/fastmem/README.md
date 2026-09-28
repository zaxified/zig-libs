# fastmem

**A vectorised `memset`** that an executable linking no libc can export to
replace compiler_rt's, which in Zig 0.16 stores one byte per iteration. Every
runtime-length `@memset` and every `std.crypto.secureZero` in the binary — std's
own included — then runs 20–27× faster.

- **Status:** gap — without libc, std has no fast `memset` at all.
- **Model after:** musl's and Go's runtime `memclr`: full-width vector stores
  with overlapping unaligned first and last vectors.
- **Platform:** any (portable `@Vector` code). **Role:** util.
  **Concurrency:** reentrant. **Allocation:** none.

```zig
const fastmem = @import("fastmem");

// In the EXECUTABLE's root file -- replaces `memset` for the whole binary:
comptime {
    fastmem.exportSymbols();
}

// Or locally, with nothing global:
fastmem.set(buf.ptr, 0, buf.len);
```

**Opt-in, on purpose.** A strong `memset` replaces compiler_rt's weak one
for every caller in the binary, so only the owner of the binary may ask for
it; a library must never call `exportSymbols`. With libc linked it is a
compile error — libc's `memset` is already vectorised and must not be
interposed.

## Speed

ns per call, best of 5, ReleaseFast `-mcpu=native`, one core of an
i7-7920HQ (2026-09-28, loaded machine — the ratios are the point):

| call | compiler_rt | exported `fastmem` |
|---|---:|---:|
| `@memset` 256 B | 76 | 5.2 |
| `@memset` 4 KiB | 1 190 | 52 |
| `@memset` 16 KiB | 4 760 | 188 |
| `secureZero` 16 KiB | 4 813 | 181 |
| std deflate level 6, 16 KiB JSON (clears a 64 KiB table) | 284 500 | 208 700 |

Provenance: original work of the zig-libs authors (MIT). The overlapping-ends
technique is common knowledge (musl, Go runtime); no third-party source was
translated, so no NOTICE entry.
