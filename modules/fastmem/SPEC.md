# `fastmem` — specification

## What this module is, and what it is not

A `memset` and the switch that installs it. Not a general `mem*` library:
compiler_rt's `memcpy`/`memmove` are already vectorised (65–96 GB/s measured on
the same core), so replacing them buys nothing. `bcmp` in compiler_rt is also
bytewise, but nothing on a measured hot path reaches it (std's `mem.eql` has its
own vector loop); add it here when a profile shows it.

## Algorithm

- `len < 32`: two overlapping stores of the widest of 16/8/4/2 bytes that fits,
  or one byte.
- `len ≥ 32`: an unaligned 32-byte store at the start and one ending at the last
  byte, and aligned 32-byte stores from the first 32-aligned address after the
  start up to the start of the last vector. Every byte in range is written at
  least once, none outside it.

All stores are `volatile`. Required, not incidental: LLVM rewrites a store loop
into a call to `memset`, which here is the function itself. A `volatile` store is
never merged or rewritten; the loop issues the same full-width stores either way.

## The export

`exportSymbols()` does `@export(&memset, .{ .name = "memset", .linkage = .strong })`.
compiler_rt exports `memset` weak ("we prefer weak linkage because some of the
routines we implement here may also be provided by system/dynamic libc",
`lib/compiler_rt/common.zig`), so the strong symbol wins at link time for every
reference, including the ones LLVM emits for `@memset` and for the volatile
`@memset` inside `std.crypto.secureZero`. Proven by a test that resolves the
linked `memset` with `@extern` and compares its address to this module's.

**Policy.** Opt-in by the executable. Replacing a symbol process-wide is not a
library's decision, so no module of this collection calls `exportSymbols`, and a
consumer that never calls it sees no change. `builtin.link_libc` makes it a
compile error: interposing libc's tuned `memset` would be a regression, and in a
dynamically linked program it would also replace `memset` for every shared
library loaded into it.

## Anchoring

- Every length 0..300 at every offset 0..63 for three fill values, with the bytes
  around the range checked untouched — covers every arm (small, one vector, head +
  middle + tail) and every alignment of the middle.
- Page-scale lengths (4095..12289) at odd offsets.
- C semantics: returns `dest`, uses the low byte of `c`, `len == 0` writes nothing.
- The test binary itself exports the symbol, so the whole test runner's own
  `@memset`s run through it, and one test proves the linked `memset` is this one.
- Shown to go red: moving the middle loop's start one vector later fails the first
  two tests (2026-09-28).

The expected bytes are computed per position from `memset`'s definition
(C11 7.24.6.1), independently of the code under test; there is no outside
corpus to agree with.

**Anchor grade:** class C · oracle n/a

## What is deliberately not done

- `rep stosb`: faster than vector stores only past a few KiB on ERMSB CPUs and
  worse on some AMD parts; the vector loop already runs at L1 store bandwidth for
  the sizes measured (4–16 KiB). Revisit with a profile showing large clears.
- Non-temporal stores for huge buffers: no caller clears more than a few hundred
  KiB at a time.

## Open

- Delete this module once std's compiler_rt `memset` is vectorised (check on each
  Zig upgrade: `lib/compiler_rt.zig`, `pub fn memset`).
