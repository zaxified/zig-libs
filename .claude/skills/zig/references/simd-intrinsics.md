# Hardware SIMD intrinsics (beyond `@Vector`)

`@Vector` gives *portable* SIMD (add/mul/`@reduce`/`@shuffle`/`@select`). It is **not**
a substitute for hardware intrinsics: there is no `@Vector` form of `udot`, `vpsadbw`,
`vpmaddubsw`, `vpmaddwd`, AVX-512 conflict-detect, etc. Zig has **no native intrinsics**
and won't add them (ziglang/zig#7702, closed "not planned"). When porting `vdotq_u32`,
`_mm256_madd_epi16`, … you need one of the two escape hatches below.

## Escape hatch #1 — LLVM intrinsics via `extern fn` (PREFERRED)

Declare the LLVM target intrinsic as an `extern fn` with its dotted name in `@"..."`:

```zig
const i8x32 = @Vector(32, i8);
const u64x4 = @Vector(4, u64);
extern fn @"llvm.x86.avx2.psad.bw"(a: i8x32, b: i8x32) u64x4;        // VPSADBW ymm
extern fn @"llvm.aarch64.neon.udot.v4i32.v16i8"(
    acc: @Vector(4, u32), a: @Vector(16, u8), b: @Vector(16, u8)) @Vector(4, u32); // UDOT

inline fn sad(a: @Vector(32, u8), b: @Vector(32, u8)) u64x4 {
    return @"llvm.x86.avx2.psad.bw"(@bitCast(a), @bitCast(b)); // bitcast u8→i8 (free)
}
```

Why preferred over inline asm: **the optimizer sees through it** — register allocation,
instruction scheduling, *and loop unrolling* all work, matching clang's codegen from the
C intrinsic. (Inline asm emits the same instruction but is an opaque barrier — see #2.)

Names follow `llvm.<arch>.<feature>.<op>`. Vector arg/return types must match the
intrinsic's exact LLVM signature (element type and lane count) or you get a selection
error. Ones verified working (Zig 0.16/0.17, LLVM backend):

| op | 128-bit (SSE) | 256-bit (AVX2) | 512-bit (AVX-512) | result |
|---|---|---|---|---|
| psadbw | `llvm.x86.sse2.psad.bw` | `llvm.x86.avx2.psad.bw` | `llvm.x86.avx512.psad.bw.512` | `<N x i64>` |
| pmaddubsw | `llvm.x86.ssse3.pmadd.ub.sw.128` | `llvm.x86.avx2.pmadd.ub.sw` | `llvm.x86.avx512.pmaddubs.w.512` | `<2N x i16>` |
| pmaddwd | `llvm.x86.sse2.pmadd.wd` | `llvm.x86.avx2.pmadd.wd` | `llvm.x86.avx512.pmaddw.d.512` | `<N x i32>` |

AArch64 NEON: `llvm.aarch64.neon.udot.v4i32.v16i8`, `.sdot.*`, `.uaddlp.*`, etc.
`vaddq`/`vshlq`/`vdupq` map directly to `@Vector` ops (`+`, `<<`, `@splat`) — only the
"weird" ops need the intrinsic.

**Caveats:** LLVM-backend-specific (the self-hosted x86_64 backend won't have these),
undocumented, and some intrinsics error in instruction-selection. Always compile-check.

## Escape hatch #2 — inline asm (portable, but optimizer-opaque)

Use when no LLVM intrinsic exists or you target a self-hosted backend. Matches the
instruction but **blocks the optimizer** (no regalloc across it, no unrolling, no CSE).

```zig
inline fn vdotq_u32(acc: u32x4, a: u8x16, b: u8x16) u32x4 {     // AArch64 NEON
    var r = acc;
    asm ("udot %[r].4s, %[a].16b, %[b].16b"
        : [r] "+w" (r) : [a] "w" (a), [b] "w" (b));               // "w" = SIMD/FP reg
    return r;
}
// x86 AT&T, VEX 3-operand order is reversed: `OP src2, src1, dst`. "x" = xmm/ymm reg.
inline fn madd(a: i16x16, b: i16x16) i32x8 {
    return asm ("vpmaddwd %[b], %[a], %[r]"
        : [r] "=x" (-> i32x8) : [a] "x" (a), [b] "x" (b));
}
```

Two failure modes we hit with inline asm (both vanish with LLVM intrinsics):
- **Rematerialization:** const tables got reloaded from `.rodata` every iteration
  instead of staying in registers. Workaround: launder through empty asm so LLVM keeps
  them resident — `asm volatile("" : [t] "+w" (t));` after loading each table.
- **No unrolling:** clang unrolled the C loop ~3×; the asm version stayed 1× (~2% slower).

## Gotchas that cost real performance

- **Keep the intrinsic's natural result layout.** `psadbw` returns `<N x i64>` (one sum
  per 64-bit lane). Accumulating it as `u32x(2N)` via `@bitCast` made LLVM *repack* the
  result with ~20 permute instructions **per iteration** (27% slower on AVX-512).
  Fix: accumulate in `u64xN` (direct `vpaddq`); combine to scalars after the loop, since
  `@reduce` and `<<` distribute over the sum.
- **`comptime` for "`const int` mode" params.** zlib-ng's `Z_FORCEINLINE … const int COPY`
  specializes into two functions. A *runtime* `COPY: c_int` in Zig produces one shared
  function with a branch in the hot loop. Use `comptime COPY: bool`.
- **Manual unroll to match clang.** LLVM often won't unroll a loop with a loop-carried
  accumulator; unroll 2–4× by hand (process N×width bytes/iter) to recover the last few %.
- **Loading a comptime array into a vector:** cast to an *array* pointer, not a vector
  pointer (`@as(*align(1) const [16]u8, @ptrCast(p)).*`) — a `*@Vector` deref of comptime
  data errors with "comptime dereference requires … well-defined layout".
- `@splat(x)` works for arrays too (0.17), and parses cleanly where `[_]T{x} ** N` can trip
  the `**` whitespace rule.

## Cross-arch validation workflow (Apple Silicon dev box)

Zig cross-compiles to anything; the hard part is *running* it to check correctness/perf.

- **x86 → Rosetta 2.** Build `-target x86_64-macos -mcpu=x86_64_v3` (AVX2) and just run
  the binary — Rosetta translates it. AVX2 needs **macOS 15 Sequoia+**. Rosetta does
  **not** support AVX-512. SSE/SSSE3/SSE4.2 work (`-mcpu=nehalem` for genuine legacy
  encodings, since `_v3` promotes to VEX).
- **AVX-512 / other ISAs → real hardware.** Build a **static musl** binary
  (`-target x86_64-linux-musl -mcpu=skylake_avx512`), `scp` it to a box with the ISA,
  run natively. (Homebrew's `qemu` on macOS ships **system-mode only**, no `qemu-x86_64`
  linux-user; build qemu-user from source for riscv64 etc.)
- **Compare against C** by compiling zlib-ng/etc with `zig cc -target … -mcpu=… -c file.c`
  and linking the `.o` into a Zig bench (`build-exe … file.o`). Same timer, same buffer.
- **Emulation and microbench noise hide real gaps.** The 27% AVX-512 repack bug was
  invisible under Rosetta/noise and only showed on native hardware. To find the *cause*,
  diff the disassembly: `objdump -d --disassemble-symbols=<sym> bin` for both, count the
  hot-loop instructions (extra `vperm*`/`ldr`/`mov` = the optimizer barrier or a layout
  mismatch). Zig symbols are namespaced: `module.funcName` (no leading `_` on ELF).

> Emit Zig asm for inspection without a runner via export wrappers:
> `zig build-obj -O ReleaseFast -mcpu=<cpu> -femit-asm=out.s --dep m -Mroot=wrap.zig -Mm=src.zig`
> where `wrap.zig` has `export fn dump(...) ... { return src.hot(...); }` (forces codegen
> of otherwise-tree-shaken `pub` fns).
