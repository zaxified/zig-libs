# Zig Gotchas (found in production code, checked on 0.17.0)

Traps that compile cleanly and look idiomatic, each found in real code and confirmed against
the std source or by measurement. Most produce no error at all: the program runs and is
wrong, slow, or leaks. They were found on 0.16.0; each entry says whether 0.17.0 still has it.

## New in 0.17.0

### The build configuration is cached on inputs it cannot see
`zig build` caches what `build.zig` configured and skips the configurer when the key — `-D`
and CLI options, target, the `build.zig` sources, declared dependencies — is unchanged. A
`build.zig` that scans a directory (a module list), reads a file or reads an environment
variable keeps building the old graph after that input changes. Measured on 0.17.0 with a
`build.zig` that counted the entries of a directory and read an env var into `b.addOptions()`:
a file added to the directory and the variable changed from `one` to `two` were both ignored,
silently; `--cache-poison=disallowed` did not catch it because the configurer never ran.

```zig
// Directory and file inputs: declare them.
b.dependOnDirectoryContents(b.path("modules"));    // entries added/removed/renamed; not recursive
b.dependOnFileContents(b.path("modules.zon"));
// Environment: no declaration exists. Prefer a -D option; otherwise
const level = b.graph.environ_map.get("MY_LEVEL");
b.graph.poisonCache(); // configuration now reruns on every zig build
```

`b.findProgram` poisons the cache itself; `b.findProgramLazy` does not. One stale run can be
forced with `zig build --cache-poison=poisoned`.

### Signed to narrower unsigned `@intCast` / `std.math.cast` is poison in optimized builds (#37131)
Open compiler issue #37131 (a fix PR was open and unmerged on 2026-10-18), present in 0.17.0 (0.16 emitted a plain `trunc`). The frontend lowers a cast from a
**signed** integer to a **narrower unsigned** one to LLVM `trunc nsw`; for an unsigned
destination it should be `nuw`. `nsw` claims the value fits as a *signed* number, so every
value in `[2^(N-1), 2^N)` is poison and LLVM may fold away whatever depends on it. Debug does
not show it. It does not depend on the target (a migration saw it on x86_64 and aarch64) and the cast is
fully defined by the language when the value was checked to fit first.

```zig
// WRONG (0.17): the range check below is folded away in ReleaseSafe/ReleaseFast
noinline fn f(eb: i64) u32 {
    if (eb < 0 or eb > 0xFFFF_FFFF) return 1;
    const v: u32 = @intCast(eb);      // std.math.cast(u32, eb) emits the same `trunc nsw`
    if (v > 0x7FFF_FFFF) return 2;    // eb = 0xFFFF_FFFF: Debug 2, ReleaseSafe/ReleaseFast 0
    return 0;
}
// RIGHT: the narrowing is unsigned to unsigned (`trunc nuw`)
noinline fn g(eb: i64) u32 {
    if (eb < 0 or eb > 0xFFFF_FFFF) return 1;
    const w: u64 = @intCast(eb);
    const v: u32 = @intCast(w);       // or @truncate(@as(u64, @bitCast(eb))) after the check
    if (v > 0x7FFF_FFFF) return 2;
    return 0;
}
```
Probe on 0.17.0 (`f` and `g` called with `0xFFFF_FFFF` passed through
`std.mem.doNotOptimizeAway(&y)`): Debug passes; ReleaseSafe and ReleaseFast fail for `f`
(`expected 2, found 0`); `g`, the `@truncate` form and `std.math.cast(u32, w)` via a `u64` pass in
all three modes. `f` with `std.math.cast(u32, eb) orelse return 3` in its place passed in this
shape: the IR is `trunc nsw` all the same, whether a body fails is the layout dependence
described below. A `std.math.cast` body that did fail: an SNMP-style
`std.math.cast(u32, eb) orelse return error.X; if (v > maxInt(i32)) return error.InvalidValue`
after a DER integer decode, ReleaseSafe/ReleaseFast `expected error.InvalidValue, found
4294967295`. A plain `var x: i64 = 0xFFFF_FFFF; _ = &x;` argument to `f` did not fail either;
as an `export fn` the optimized IR shows the `> 0x7FFF_FFFF` branch folded away.

**The range check belongs in every spelling.** `@intCast` of a negative signed value to the
same-width unsigned type is illegal behaviour (panic in safe builds, a wrong value in
ReleaseFast), so `const w: u64 = @intCast(x)` is only right after `x < 0` was excluded. The
spelling that carries its own check, run in Debug, ReleaseSafe and ReleaseFast:
```zig
const w = std.math.cast(u64, x) orelse return error.OutOfRange; // negative -> error
const v = std.math.cast(u32, w) orelse return error.OutOfRange; // too large -> error
```

Flags per cast shape in the pre-optimization IR (re-run on 0.17.0 with `--verbose-llvm-ir` in
ReleaseFast and with Debug `-femit-llvm-ir`, same classification; 0.16.0: a plain `trunc`
everywhere): `i64 -> u32`, `i32 -> u16`, `i16 -> u8`, `isize -> u8`:
`trunc nsw` (wrong); `i64 -> i32`: `nsw` (right); `u64 -> u32`, `usize -> u8`, `u64 -> i32`:
`nuw` (right); `i64 -> u64`: no trunc; `i64 -> u64 -> u32` as two `@intCast`s: `nuw`.

Whether it bites depends on layout: the poison is always there, but LLVM exploits it only in
some shapes (one suite passed with the narrowing in a `noinline` helper and failed
with the same body in an `inline fn`). A test that does not fail is no evidence
that a site is fine, and no test can force LLVM to exploit the poison: pin the boundary
values, and prefer the unsigned-to-unsigned spelling at every site. Shapes that lower to the
same cast and were found in a 57-module codebase: `@intCast`, `std.math.cast`,
`std.math.clamp`, `@max(0, x)` / `@min` whose result type is narrowed, `std.json` into unsigned
fields from a `Value` (`parseFromValue`) or from a float-formatted number such as `4e9`
(`json/static.zig`; plain integer text goes through `std.fmt.parseInt` and is fine), and `std.math.pow` through `ldexp`
(`math/ldexp.zig`). A tree-wide detector scans pre-optimization IR (Debug with
`-femit-llvm-ir` is enough: the classification does not depend on the mode) for a `trunc nsw`
whose source is bounded below by `icmp sge x, 0`; an unsigned destination with an `nsw` trunc is
this bug. Remove the workarounds once a release fixes it, and name the issue in their comment.

### `zig build` lost flags scripts use
Measured ("unrecognized argument"): `--global-cache-dir` (use `ZIG_GLOBAL_CACHE_DIR`),
`--zig-lib-dir` (now `--zig-lib=`, first argument only), `--build-runner`, `--verbose-llvm-bc`.
`b.cache_root` and `b.graph.global_cache_root` are gone, so configure code can no longer put a
cache path into a string; a step can still take `std.Build.LazyPath.cache_root`. `--release=ReleaseSafe` fails (`--release=safe`), while `-Doptimize=ReleaseSafe`
and `-OReleaseSafe` still work — keep the old spellings in scripts that must also run on 0.16.

### Silent behaviour changes
- **`@bitCast` of arrays and vectors** now reinterprets logical bits, element 0 first: on a
  big-endian target an array-to-integer cast gives a different value than in 0.16. Little-endian
  results are unchanged. Run-verified in a migration on s390x under qemu (ReleaseSafe): dropping
  the old big-endian byte swap before such a cast took a ChaCha20-Poly1305 module from 27 to 49
  of 55 tests (0.16: 49), see SKILL.md "Silent changes". (A cast from or to an `extern struct` stopped compiling — both
  directions — so it cannot go silently wrong.) The replacement for the "bytes as they lie in
  memory" idiom (a network-order address in a `u32` field, a kernel-ABI word) is
  `std.mem.bytesToValue(u32, &bytes)` / `std.mem.toBytes(x)` (`mem.zig` `bytesToValue`,
  `toBytes`); for a fixed wire order `std.mem.readInt(u32, &bytes, .big)` /
  `std.mem.writeInt(u32, &bytes, x, .big)`.
- **`@hasDecl` is `false` for a non-`pub` declaration**, also from inside the same file. A
  `comptime` feature probe written as `@hasDecl(Self, "helper")` on a private helper flips to
  `false` and silently takes the fallback path. The same flip hits option declarations a
  consumer supplies for a library that probes them with `@hasDecl` (without `pub` the option
  is ignored, which can change a wire format or a default): list the probes with `rg '@hasDecl'`.
- **`std.mem.containsAtLeastScalar(T, list, element, minimum)`** swapped its last two
  parameters. With `u8`/`usize`-compatible integers an old call still compiles and answers a
  different question.
- **`std.testing.allocator` is a fresh `SafeAllocator` per test that hands memory back.** It
  returns a large allocation and every emptied 8 KiB bucket to `page_allocator`, so a long
  alloc/free loop stays flat (probe on 0.17.0, 2 000 000 x 64 B in one test: RSS 700 -> 708 KiB
  in ReleaseSafe). Slots inside a bucket are never reused, so long-lived small allocations
  mixed with short-lived ones pin whole buckets (same probe, 1 in 64 kept: 195 KiB live, RSS
  748 -> 14988 KiB). Use-after-free turns into a segfault or a panic much more often (good);
  writes after free are checked in every mode; allocation stack traces exist only in Debug.
  A fuzz or property loop that runs thousands of seeds inside one test can still create one
  `std.heap.SafeAllocator` per seed (`.init(gpa, .{ .stack_trace_frames = 0 })`, `deinit()` returns
  the leak count, `deinitLog(false)` is the silent form) for per-seed leak attribution and to
  drop pinned buckets between seeds. Because
  `SafeAllocator` can resize in place, `FailingAllocator` `fail_index` values pinned in 0.16
  tests may no longer be reached: take them from `alloc_index` of a clean run.
- **`Reader.allocRemaining(gpa, .limited(n))` accepts exactly `n` bytes** (0.16 failed at `n`;
  `Io/Reader.zig` `allocRemaining` passes `n + 1` to `appendRemaining`, which fails when its
  limit is *reached*). Every body/size limit built on it shifts by one: check each call site and
  its over-limit test (a test written for `n` bytes may now pass silently; a limit that meant
  "< n" is now "<= n"). Adjust the argument, not the documented limit. `appendRemaining` itself
  is unchanged. `Limit.limited(std.math.maxInt(usize))` is `.unlimited` in this function
  (`allocRemaining` maps `.unlimited` through unchanged and adds the 1 itself, `Io/Reader.zig`
  `allocRemaining`), so a call site that wrote `cap +| 1` or special-cased `maxInt` to avoid the
  overflow should pass `.limited(cap)` and map an "unbounded" cap to `.unlimited`.
- **`std.json.parseFromSlice(std.json.Value, ...)` needs a little more memory in Debug.** A 35-byte
  object document took 2052 bytes from a `FixedBufferAllocator` on 0.16.0 and 2228 on 0.17.0
  (Debug, same probe file; ReleaseFast: 2048 bytes on both; a migration test with a 4 KiB arena for a 47-byte document ran out of
  memory). Size fixed buffers and arenas for `std.json` with a margin, not to the byte.
- **A struct returned by value must not hold a slice into its own array field.** This is
  undefined in every version; 0.17 exposed it in a migration (the copy happens, so `.val = self.buf[0..k]` points at the
  callee's dead frame) (found as a panic in a websocket parameter iterator). Store an offset and
  length and slice at use, or let the caller own the buffer.

### Tooling
- **ZLS does not work with 0.17.0** (the build runner it hooked into is gone). Editor
  diagnostics stay empty or stale; compile to see errors.
- **The first `zig build` after installing 0.17 compiles the maker** (measured twice:
  108 s and 115 s, Zig 0.17.0, x86_64 Linux, 8-core machine; once per toolchain and global cache). A fresh CI runner pays it on every job unless
  the global cache (`~/.cache/zig`) is cached; a CI script that gives every lane its own
  `ZIG_GLOBAL_CACHE_DIR` pays it once per lane. On a developer machine the cache usually already
  has the maker from another 0.17 project (a first build of a small project, ~4.3k
  lines, took 5.7 s in total; maker already in the global cache, Zig 0.17.0, x86_64 Linux, 8-core machine).
- **Custom build steps (`makeFn`) no longer exist** — see SKILL.md "Build system" for the
  host-tool + Run-step replacement.
- **`zig build` prints a trailing `failed command: <test binary> ... --listen=-` line after
  the output of a test that wrote to stderr, although the step succeeded** (reproduced on
  0.17.0 with a one-test project whose test calls `std.debug.print`: exit code 0, summary
  `test success`). It is not an error; judge by the exit code and the Build Summary.
- **Cache manifests in `.zig-cache/h/` are binary.** A script that parsed them as text (a
  coverage or cache-inspection tool) breaks; `zig cache-cat <path>` prints one as ZON.
- **LLVM 22.** Code generation changed: redo constant-time checks of the binary (valgrind
  taint, objdump) and benchmark baselines. Loop vectorization is still disabled, as in 0.16.
  Seen in a migration: LLVM 22 split `if (invalid != 0)` (with `invalid` built from two
  or-ed masks) into two conditional jumps to the same reject block, i.e. one control-flow path
  per failure reason in a padding check that must have one (an AES-CBC unpadder, found by
  ctgrind; whether it splits depends on the inlining context the consumer chooses). Fix: fold
  the flag first and pass it through an empty-asm barrier before the single branch
  (`asm volatile ("" : [v] "+r" (flag));` — guard it with `@inComptime()`, inline asm cannot
  run at comptime), and test that the barrier's verdict equals a branchy reference.
  A second case from the same migration (found by objdump of a ReleaseFast build): a secret
  mask `key.cw_final & (0 -% bit)` became `test $1,%r13b; je` over the load of `cw_final`, a
  jump on the secret bit. Fix: build the mask once in a single `usize` word passed through the
  same empty-asm barrier, replicate it to the element width, guard with `@inComptime()`, and
  check the result equals a branchy reference (taken from the migration report; the objdump
  was not re-run for this skill).
- **LLVM 22 can tail-merge identical branch tails of inlined functions into one instruction
  that has no source line.** valgrind/DWARF then reports `main (harness.zig:0)` and the
  library frame is missing from the stack, so a tool that counts "contexts inside the module
  file" sees the count drop (1 to 0) while the branch still exists: a fail-open attribution
  (observed in a ctgrind harness whose two AES-CBC unpadders were inlined into `main` and their
  identical vector-scan tails merged, ReleaseFast). Call each routine under test through its own
  `noinline fn strip(comptime f: anytype, buf: []u8)` instance (the routine is still inlined
  into it, but never merged with another), and compare the count against a pin.
- **Frame paths in 0.17 debug info are package-relative** (`std/Io/Writer.zig:1944`,
  `modules/<m>/src/x.zig:80`), while compiler_rt frames stay bare (`memcpy.zig`). A tool that
  parses stack traces or valgrind frames and compares the whole path against `Writer.zig` or
  `foo.zig` matches nothing now: key on the basename, and require a `std/` directory when you
  mean the standard library.
- **Known 0.17.0 regressions** (release notes): response files in `std.Build.Step.Run`
  (#36444, a casualty of the configurer/maker split), `std.debug.simple_panic` does not
  compile (#36986), weak symbols of Zig's libc cannot reliably be overridden, soft-float
  compiler-rt on x86 (#37006), SPIR-V (#37050).
- **`std.Io.Uring` has no networking** (`netListenIp`, `netAccept`, `netConnectIp` return
  `…Unavailable`) and there is no epoll backend; network servers stay on `std.Io.Threaded`.
- **`ArrayList` gained `pointer_stability`** (a `std.debug.SafetyLock`). A field-by-field
  literal stops compiling; `.empty` and `initBuffer` are unaffected. `lockPointers()` /
  `unlockPointers()` make any growth while a pointer into the list is held trip an assertion
  in safe builds.

## Language

### `a, b = .{ b, a }` is not a swap

Still true in 0.17.0.

Result-location semantics build the tuple straight into the destinations: `a` is assigned
`b` first, then `b` reads the already-overwritten `a`. Both end up equal.

```zig
// WRONG: both become the old value of b
a, b = .{ b, a };

// CORRECT: plain temporary, stays in registers
const tmp = a;
a = b;
b = tmp;
```

`std.mem.swap(T, &a, &b)` is correct, but on hot locals it forces them to memory; a
measured case reassembled two `u32` locals byte by byte (+16 % instructions in a
compressor inner loop). Only a byte-exact golden test told the "speedup" apart from the bug.

### A generic struct that never names its parameter is one type

Still true in 0.17.0.

A type's identity is its declaration site plus the comptime values it captures. If the
returned struct never references the parameter, every instantiation is the same type and
its container-level `var`s are shared.

```zig
// WRONG: Store(a) == Store(b); `doc` is shared by every config
fn Store(comptime config: Config) type {
    return struct {
        var doc: ?[]const u8 = null;
    };
}

// CORRECT: capture the parameter inside the struct
fn Store(comptime config: Config) type {
    return struct {
        const for_config = config;
        var doc: ?[]const u8 = null;
    };
}

test "one type per config" {
    try std.testing.expect(Store(.{ .id = 1 }) != Store(.{ .id = 2 }));
}
```

### `@bitCast` between a byte array and wider lanes compiles to a byte loop

New in 0.17.0 (LLVM 22), performance only: `@bitCast` from `[N]u8` to a vector of wider lanes
(or to a 16-byte-or-larger integer), and back, is lowered byte by byte (movzbl/shld over a wide
integer) instead of one vector load. Same logical little-endian result, about 9-26x the instructions in the cases measured below.
Vector-to-vector `@bitCast` and `[N]u8` <-> `@Vector(N, u8)` coercion are plain vector moves,
so go through the byte vector:

```zig
// SLOW on 0.17: byte-by-byte loop
fn load(p: *const [16]u8) @Vector(2, u64) { return @bitCast(p.*); }

// FAST: coerce to @Vector(16, u8), then vector -> vector @bitCast (one vmovdqu)
fn load(p: *const [16]u8) @Vector(2, u64) {
    const v: @Vector(16, u8) = p.*;
    return @bitCast(v);
}
```

Same for the store direction: `@as(@Vector(16, u8), @bitCast(lanes))` assigns to a `[16]u8`.
The meaning is little-endian-logical on every target, so no endian branch is needed.

Measured here (`zig build-obj -OReleaseFast -target x86_64-linux -mcpu=x86_64_v3`, objdump
instruction count per function including `ret`): `[16]u8` -> `@Vector(2, u64)` 52 direct vs 6
via `@Vector(16, u8)`; `[32]u8` -> `@Vector(8, u32)` 157 vs 6. A migration of a Poly1305
implementation saw 6 -> 51 and 8 -> 142 versus 0.16 for the same casts (14.5x total
instructions in the hot function); the byte-vector detour fixed it. Other targets not measured.

### `@intFromFloat` out of range is illegal behaviour

Still true in 0.17.0 (safe modes panic: "integer part of floating point value out of bounds").

Not wrapping, not saturating: a panic in safe modes, an arbitrary value in ReleaseFast.
`std.fmt.parseFloat(f64, "1e999999")` succeeds and returns `inf`, so any parser that turns
a JSON number into an integer this way can be crashed by a 14-byte document such as
`{"t":1e999999}`.

```zig
fn toI64(f: f64) ?i64 {
    if (!std.math.isFinite(f)) return null;
    if (f >= @as(f64, @floatFromInt(std.math.maxInt(i64)))) return null;
    if (f <= @as(f64, @floatFromInt(std.math.minInt(i64)))) return null;
    return @intFromFloat(f);
}
```

Pair the guard with a test that an in-range float still converts, or the fix can silently
disable the feature.

### A failed `try` in a union literal has already written the tag

Still true in 0.17.0. Result-location semantics write the destination's tag before the payload
expression runs; when `try` returns, the destination is left with the new tag and an undefined
payload.

```zig
// WRONG: on error, `o.*` is `.b` with garbage, not the old value
o.* = .{ .b = try fail() };

// CORRECT: evaluate first, then assign
const v = try fail();
o.* = .{ .b = v };
```

## std.debug

### `getSymbols` with a stack-tracing allocator deadlocks

Measured on 0.16.0 and 0.17.0: `std.debug.SelfInfo.getSymbols` takes the debug-info lock
exclusively and then allocates. If the allocator records a stack trace per allocation — a
`SafeAllocator` in Debug, which is what `init.gpa` and `std.testing.allocator` are — that
allocation unwinds the stack, which needs the same lock: the process hangs on a futex. Pass
`std.debug.getDebugInfoAllocator()` (what std itself uses) for both the symbol list and the
text arena.

## std.Io

### Cancellation is erased at the `Io.Reader` boundary

Still true in 0.17.0 (`Io.Reader.Error` is unchanged).

`std.Io.Reader.Error` is `{ ReadFailed, EndOfStream }`. Cancelling a future blocked in a
socket read works (measured: returns in under 1 ms), but code holding a `*std.Io.Reader`
only sees `error.ReadFailed`. The real cause, `error.Canceled`, is in the concrete
reader's `err` field.

```zig
const byte = reader.interface.takeByte() catch |e| switch (e) {
    error.ReadFailed => return reader.err orelse error.ReadFailed, // Canceled lives here
    else => |other| return other,
};
```

A protocol module that must tell cancel from I/O failure has to take the concrete reader,
or its caller has to inspect `.err` after `ReadFailed`. Do not flatten errors into
`ReadFailed` at module boundaries.

### `std.Io.fiber.contextSwitch` miscompiles when inlined

Still true in 0.17.0 (the function is byte-identical).

Its inline asm lists `rsi` (aarch64: `x1`) as output, input and clobber. clang rejects the
same shape in C; Zig passes it to LLVM, and under register pressure the asm is entered with
a stale `rsi`, crashing at address `0xaa` in ReleaseSafe. Whether it bites depends on the
surrounding code, so a small test program does not reproduce it. Tracked upstream as
Codeberg ziglang/zig issue 35724.

Code that drives fibers directly: use a `noinline` copy of `contextSwitch` whose clobber list
omits the input register, with a comment naming the issue so it can be removed once a release
fixes it.

## Testing and fuzzing

### Fuzz corpus entries lose their first four bytes

Still true in 0.17.0 (`Smith` decodes input the same way; the fuzzer did not change).

`std.testing.Smith.slice` reads a 4-byte little-endian length from the input before the
bytes. A raw seed passed as `.corpus = &.{"GET / HTTP/1.1..."}` loses its first four bytes
to that length, so the seed never reaches the code it was written for.

- Prefix every seed with its length (a small helper that builds the encoded entry).
- Call `slice` first in the harness.
- Add a test that decodes each seed through `Smith{ .in = entry }` and asserts it reaches
  the intended branch.

`zig build test --fuzz` exits 0 even when it found a crash, shows no progress and does not
report a hang (found on 0.16; the 0.17.0 release notes: "no changes were made to the
fuzzer"). Never take a verdict from its exit code: drive the same harness from a deterministic
seed loop in an ordinary test binary, with a timeout per input.

The fuzzer explores raw bytes poorly; give harnesses a structured half built from
`smith.value(T)` and friends. See [std.testing](std-testing.md).

### Two backends: self-hosted for the edit loop, LLVM for test runs

Still true in 0.17.0. The timings below are from 0.16.0. New in 0.17: `-fincremental --watch`
makes the self-hosted edit loop near-instant (measured 14 ms and 6 ms per edit of a 10-line
program, Zig 0.17.0, x86_64 Linux, 8-core machine), while an LLVM build gains nothing from it (a full 2–3 s
rebuild per edit).

A Debug build for x86_64 Linux uses the self-hosted backend; every Release mode, and Debug on
most other targets, uses LLVM. `builtin.zig_backend` says which one built the code
(`.stage2_x86_64` or `.stage2_llvm`). The self-hosted backend compiles much faster and emits
much slower code, so it pays off only while the code is being edited.

Measured on Zig 0.16.0, x86_64 Linux, eight modules of one library (0.5 k to 30 k lines):
rebuild after an edit (without `-fincremental` the whole test binary is recompiled) plus the
test run, in seconds, best of two runs on a shared 8-core machine; "over N" is a run stopped
at that limit.

| module | self-hosted Debug | LLVM Debug | ReleaseSafe | ReleaseFast |
|---|---|---|---|---|
| CRC-32C (0.5 k lines) | 1.9 + 0.3 | 4.7 + 0.5 | 22.2 + 0.1 | 22.6 + 0.1 |
| JSON5 parser | 0.9 + 0.5 | 4.1 + 0.6 | 22.9 + 0.3 | 23.9 + 0.3 |
| secp256k1 | 4.1 + 25.6 | 8.4 + 7.8 | 29.1 + 4.2 | 30.2 + 4.2 |
| MLS | 2.0 + 61.2 | 8.1 + 29.7 | 47.0 + 6.1 | 54.0 + 4.0 |
| SSH | 2.1 + 42.2 | 11.3 + 42.2 | 68.7 + 16.8 | 57.1 + 17.0 |
| zstd (30 k lines) | 9 + over 600 | 53 + over 600 | 200 + over 180 | 146 + 132 |

- Self-hosted compiles 2 to 6 times faster than LLVM Debug, but its code runs 2 to 3 times
  slower: for compute-bound tests the edit-and-test loop is slower than with LLVM Debug.
- Release modes carry a floor of about 20 s even for a 500-line module (LLVM optimizes std
  and the test runner too). LLVM Debug builds 3.5 to 6 times faster than ReleaseSafe.
- A suite that does not finish in Debug within minutes needs an optimized mode for every run.

Which build for what:

- **Editing** ("does it compile", a quick test while typing): the default Debug build.
- **Running tests while iterating**: Debug with LLVM. Same safety checks, faster code.
- **Before a release**: ReleaseSafe (the mode most programs ship in) and ReleaseFast. Only an
  optimized build shows bugs that depend on inlining (`@frameAddress()`, `@returnAddress()`),
  wrong inline-asm constraints (register allocation differs), code relying on an `assert`
  that ReleaseFast compiles out, and reads of `undefined`, which Debug and ReleaseSafe fill
  with `0xaa`.
- **valgrind, timing, constant-time checks, fuzzing throughput, benchmarks**: ReleaseSafe or
  ReleaseFast. Under valgrind a self-hosted build produced tens of thousands of
  `DWARF2 reader` warnings and wrong line numbers for most frames.

`zig build` has no switch for the backend; it is set per compile step. `zig test`,
`zig build-exe` and `zig run` take `-fllvm` / `-fno-llvm`. In `build.zig`, one option,
passed to every `addTest`, `addExecutable`, `addLibrary` and `addObject`:

```zig
// Self-hosted backend only on request, for the edit loop.
const selfhosted = b.option(bool, "selfhosted", "Use the self-hosted backend (edit loop only)") orelse false;
const use_llvm: ?bool = if (selfhosted) null else true;

const tests = b.addTest(.{ .root_module = mod, .use_llvm = use_llvm });
```

`use_llvm = true` changes nothing in Release modes, which use LLVM already.

## Performance

### `std.HashMap` never rehashes away its tombstones

Still true in 0.17.0.

`remove` leaves a tombstone and increments `available`; growth is triggered only by
`available`. A long-lived map with a remove-one-insert-one pattern (a cache under misses)
never rebuilds, tombstones accumulate until no free slot is left, and every lookup of an
absent key walks the whole table. Measured: 697 k instructions per lookup at 1 024 entries,
30 k after the fix.

```zig
// Count removals yourself and rebuild periodically.
if (self.removed_since_rehash >= self.map.capacity() / 4) {
    self.map.rehash(ctx); // managed maps: self.map.rehash()
    self.removed_since_rehash = 0;
}
```

### `memcmp` and `secureZero` are byte loops

0.17.0 vectorized `compiler_rt.memset` (byte-wise only in ReleaseSmall), so the 0.16 trap
"without libc, `@memset` is about 18x slower than glibc" is gone. Still byte loops:
`compiler_rt`'s `memcmp`/`bcmp`, and `std.crypto.secureZero`, which is a `@memset` over volatile memory. For a large scrub on a hot
path, zero with volatile vector stores:

```zig
// Zero a 32-byte-aligned buffer whose length is a multiple of 32.
const V = @Vector(32, u8);
const words: [*]volatile V = @ptrCast(@alignCast(buf.ptr));
for (0..buf.len / 32) |k| words[k] = @splat(0);
```

### `?Big = null` and `.{}` memset the whole value

Still true in 0.17.0 (ReleaseFast, LLVM 22). Assigning `null` to an optional of a large struct,
or initializing a struct with `.{}` whose large array field defaults to `undefined`, emits a
`memset` over the whole value — 8 KiB for an 8 KiB buffer, on every call. On a hot path keep
the large buffer out of the optional (a separate `has_value` flag) and initialize only the
small fields.

## Security

### `std.crypto.ff` and `select` are not constant-time in ReleaseFast

Still true in 0.17.0 (measured with valgrind memcheck taint on ReleaseFast builds): the window
selection in `ff.Modulus.pow` and the final-subtraction check in `montgomeryMul` branch on
secret data, and LLVM 22 turns a hand-written `f64` mask select into a branch. Do not assume
`std.crypto.ff` (RSA-style big-number arithmetic) is constant-time; verify the binary, not the
source. There are such contexts on 0.17.0 too: the window select is `cmov` ->
`ct.select` per limb (`crypto/ff.zig` `cmov` and its use in `powWithEncodedExponentInternal`),
which LLVM 22 unswitches into jumps (16 valgrind contexts in one ctgrind positive-control
harness, ReleaseFast, 0.17.0; 0.16's `cmov(ct.eql)` select also compiled to jumps, but its context count for the same harness was not recorded).
The 0.17.x length fix below does not make the window select constant-time.

### std TLS does not check that an issuer is a CA: `std.http.Client` over https is open to a man in the middle

Still true in 0.17.0, and it **also hits code that never builds its own chain check**.
`std.crypto.Certificate.Parsed.verify` (`crypto/Certificate.zig:259-308`) checks the issuer
name, the validity dates and the signature, and nothing else: basicConstraints, keyUsage and
pathLen are recognised by OID but never read or enforced (`basic_constraints` is only an enum tag,
`Certificate.zig:124,145,149`). `std.crypto.tls.Client` uses exactly this check for every hop
(`crypto/tls/Client.zig:651` `prev_cert.verify(subject, now_sec)` between the certificates the
server sends, `:667` `ca.bundle.verify(subject, now_sec)` for the trust anchor, via
`Certificate/Bundle.zig:32-43`), and `std.http.Client` builds on it. So anyone who holds a
certificate that a trusted CA issued to them, for any host name, can use it to sign a
certificate for a different host and present the pair as the chain: the client accepts it.
That is an impersonation by an active network attacker; it is read from the source, and the release review reproduced it on a loopback
server (a CA:FALSE leaf signing a certificate for another name was accepted). Consequences:

- Do not rely on `std.crypto.tls.Client` or `std.http.Client` over https alone when the
  server's authenticity matters (credentials, updates, payments, remote commands).
- Pin the server's certificate (a trust bundle that holds only that certificate, see
  std-http.md "TLS Configuration", compiled and run on 0.17.0 against a loopback
  `openssl s_server`), or use a TLS library that validates the whole chain. A dependency is
  the user's decision: ask the user before adding one. The pin works only for a self-signed
  server certificate that is its own anchor; a CA-issued leaf alone is refused, putting the
  intermediate or root CA into the bundle brings the impersonation back, and
  `client.now = null` on a pinned client drops the pin.
- Code that builds its own chain check must reject an issuer without `CA:TRUE`.
- Separate defects of the same client: see the `readIndirect` entry below (do not use the
  client against untrusted servers).

### `std.crypto` leaves key schedules on the stack

Found on 0.16.0; not re-measured on 0.17.0. The AES-NI path did not change; on targets
without AES hardware the software context is now bitsliced and several KB, so the residue
is larger (see "Known 0.17.0 library behaviour").

After a TLS 1.3 handshake, the AES round keys (176-byte `AesEncryptCtx`, round key 0 is
the raw key) were found at about ten places on the dead stack below the caller.
`secureZero` on your own structs only clears the copies you own; it cannot reach frames
inside `std.crypto.aead.*`. "The key does not outlive the connection" is only true if the
stack itself is scrubbed (for example `MADV_DONTNEED` on a fiber stack before reuse). A
pooled OS thread keeps whatever was last written there.

## Build system

### `build.zig.zon` facts

Checked on 0.16.0. In 0.17.0 fetched packages are also copied into `zig-pkg/` in the project
(add it to `.gitignore`).

- `.fingerprint`: the upper 32 bits are the CRC-32 of the package name; the lower 32 are
  an arbitrary id.
- Unknown fields are ignored, at top level and inside dependency entries. A field ignored
  today can collide with a real one tomorrow, so prefix tool-specific fields
  (`.mytool_upstream`, not `.upstream`).
- A dependency URL must carry an explicit ref and the entry must have a `.hash`; a floating
  branch is rejected. Updates only arrive through a deliberate `zig fetch --save`.
- `zig build --fork=/path/to/checkout` overrides a package throughout the dependency tree
  without editing the manifest, which is safer than temporarily switching the pin to `.path`.
  With one matching package it works (run in a migration, six example apps). With two or more
  matching packages it fails on 0.17.0 according to #31677 and the fix commit's message
  (`026e105`, on the 0.17.x branch; not reproduced here).

### The self-hosted x86_64 backend cannot encode what the target CPU lacks

Still true in 0.17.0 (same `InvalidInstruction` for `pclmulqdq`, `crc32q`, `aesenc`).

A path chosen at run time by a CPUID check (`pclmulqdq`, the SSE4.2 `crc32`, AES-NI, `pshufb`
in inline asm) is compiled for every x86_64 target. LLVM assembles it for any CPU model; the
self-hosted backend encodes only instructions the target CPU model has. A Debug build for a
baseline target (`-Dtarget=x86_64-linux`, `-Dcpu=baseline`, or a CPU model without the
feature) fails with

```
error(x86_64_encoder): no encoding found for: none pclmulqdq xmm xmm imm8s none
error: emit MIR failed: InvalidInstruction (Zig compiler bug)
```

Builds for the native CPU and all LLVM builds pass, so the failure reaches only consumers who
build Debug for a generic target. Compile the path only where the backend can emit it, and
fall back to the portable code elsewhere. A test of that path must check the comptime
condition first: `return error.SkipZigTest` is a run-time return, so a test that skips only
on a run-time CPU check still compiles the asm.

```zig
const std = @import("std");
const builtin = @import("builtin");

/// The hardware path can be compiled at all: LLVM always, the self-hosted backend only when
/// the target CPU model has the instruction.
const pclmul_emittable = builtin.target.cpu.arch == .x86_64 and
    (builtin.zig_backend != .stage2_x86_64 or
        std.Target.x86.featureSetHas(builtin.target.cpu.features, .pclmul));

fn cpuHasPclmul() bool {
    if (builtin.target.cpu.arch != .x86_64) return false;
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (@as(u32, 1)),
          [_] "{ecx}" (@as(u32, 0)),
    );
    return (ecx >> 1) & 1 == 1; // CPUID.01H:ECX.PCLMULQDQ[bit 1]
}

fn clmulLow(a: @Vector(2, u64), b: @Vector(2, u64)) @Vector(2, u64) {
    return asm ("pclmulqdq $0x00, %[b], %[a]"
        : [a] "=x" (-> @Vector(2, u64)),
        : [_] "0" (a),
          [b] "x" (b),
    );
}

test "the carry-less multiply path" {
    // `pclmul_emittable` first: comptime-false, it keeps `clmulLow` out of builds that cannot
    // compile it. `cpuHasPclmul()` alone is a run-time check.
    if (!pclmul_emittable or !cpuHasPclmul()) return error.SkipZigTest;
    const r = clmulLow(.{ 3, 0 }, .{ 5, 0 });
    try std.testing.expectEqual(@as(u64, 15), r[0]); // (x + 1)(x^2 + 1) = x^3 + x^2 + x + 1
}
```

The same applies to every other gate on such a path: the dispatcher, `available()`-style
queries and test helpers all test the comptime condition before the run-time one.

### One global package cache shared by 0.16 and 0.17

Seen once, cause not isolated: after 0.17 had fetched an archive (an SQLite amalgamation zip)
into the shared global cache, a *fresh* 0.16 checkout (a new git worktree, empty `zig-pkg/`)
failed with `hash mismatch: manifest declares ... but the fetched package has ...`, and its
`zig-pkg/<hash>/` kept the archive's top-level directory unstripped. Existing 0.16 checkouts
with a filled `zig-pkg/` were unaffected, and copying the 0.16-unpacked package directory in
fixed it. While both toolchains are in use, pass a separate `ZIG_GLOBAL_CACHE_DIR=... zig build` per
toolchain (SKILL.md recommends the shared cache otherwise: that applies when only one toolchain
fetches), or ask the user before changing their environment.

### Fixed in 0.17.0

- Deleting `.zig-cache/o` no longer wedges `zig build`: the configurer reruns.
- `std.testing.allocator` leaks fail the test in ReleaseFast too (0.16 passed them silently).
- `std.process.getUserInfo(io, name)` compiles and works.

## Known 0.17.0 library behaviour (read from the 0.17.0 source)
- **`std.crypto.ff` `powWithEncodedExponent` loops over the exponent bytes as given**
  (`ff.zig` `powWithEncodedExponentInternal`): the running time reveals the encoded length.
  With a secret exponent, pass it encoded at the modulus byte length (left-padded) yourself;
  `powWithEncodedPublicExponent` is for public exponents only. A fix upstream is reported on
  the 0.17.x branch and is not in 0.17.0.
- **`ff.Fe.eql` compares limbs only** (`ff.zig` `eql` -> `x.v.eql(y.v)`, the `montgomery` flag is
  ignored): a plain and a Montgomery-form element of the same number compare unequal (and
  limbs can coincide for different numbers). Convert both operands to the same form first.
- **`std.crypto.ecdsa` reads `Curve.Fe.field_order`** (`crypto/ecdsa.zig` verify:
  `comptime assert(n < Fe.field_order and Fe.field_order < 2 * n)`): a hand-written curve type
  passed to `Ecdsa` needs a `comptime_int` `field_order` on its field type, next to the
  scalar field's. The scalar side must also be a `comptime_int`: std computes `2 * n` at
  comptime (`crypto/ecdsa.zig` verify), and a `u256` `field_order` overflowed it in a migration.
- **`std.crypto.ff.Error` gained `DivisionByZeroError`** (`crypto/ff.zig:56-59`, raised by
  `divRemPublic` and `gcdPublic`; 0.16 `ff.zig` has no `DivisionByZero`). An `else =>` arm over
  a switch on an ff error set now silently absorbs it; list the arms explicitly.
- **Soft AES is bitsliced unless `std.options.side_channels_mitigations == .none`**
  (`crypto/aes/soft.zig:6-8`, `:294`): `optimal_parallel_blocks` is `bitsliced.width` (1 on
  0.16), and the software context is large (3024 bytes on s390x, 4112 on mips in a migration
  probe). Code that sizes a buffer from `optimal_parallel_blocks` or asserts
  `@sizeOf(AesCtx)` changes on targets without AES hardware (and in tests of them).
- **`std.crypto.tls.Client` still has two unchecked paths in `readIndirect`** (from reading the
  0.17.0 source, `crypto/tls/Client.zig:1250-1270`; std itself was not run on a malicious peer,
  our copy of the 0.16 code was and crashed 3 of 3 with the checks removed). Both need an
  authenticated peer; they panic in safe builds and are undefined behaviour in ReleaseFast.
  (A) A `.handshake` record shorter than 4 bytes (or empty) indexes `cleartext[ct_i]` and
  `cleartext[ct_i..][0..3]` with no length guard before the `handshake_len` check. (B) A
  `key_update` message on a TLS 1.2 connection reads `p.tls_1_3`, the inactive union field. The
  KeyUpdate body-length check (`handshake.len != 1`) is present. If you embed this client for
  untrusted servers, patch a copy (length guard before `cleartext[ct_i]`, reject `key_update` unless TLS 1.3), or do not use it against untrusted servers. A reader in front does not help: both paths act on the decrypted record.
- **`std.crypto.tls.Client` rejects an all-zero inner plaintext in the encrypted handshake**
  with `error.TlsDecodeError` (`Client.zig:381`, `trimmed_len == 0`; the 0.16 client had no such
  check). A test that pins client error names against a fake server sees the new name.
- **`std.crypto.Certificate.der.Tag.sequence_of` is gone**; the tag is `set` (`= 17`,
  `crypto/Certificate.zig` `Tag`). `rsa.PKCS1v1_5Signature.verify` / `rsa.PSSSignature.verify`
  take `sig: *const [modulus_len]u8` (0.16: `[modulus_len]u8` by value): pass `&sig` (`Certificate.zig` `verify`).
- **`Edwards25519.fromBytes` rejects the encoding x = 0 with the sign bit set**
  (`crypto/25519/edwards25519.zig` `fromBytes`, `InvalidEncoding`), so a test that used std as a lenient reference for
  such a point now sees an error.

## Known 0.17.0 issues fixed on the 0.17.x branch

Taken from the 0.17.x branch commit log and the project's issue list. **Per the commit
message, not reproduced here** unless a row says otherwise; each row names the commit.
Check which point release you have; the last two rows are open, not branch fixes.

| Commit | Symptom (as the message states it) |
|---|---|
| `20057b4` | An array sentinel is discarded when a sentinel-terminated array is coerced to a slice |
| `026e105` (#31677) | `zig build --fork=<dir>` with two or more matching packages always fails |
| `388c02e`, `c629ee4` | `Io.net` control-message (cmsg) alignment; `Stream` read after control data |
| `d3b1f18` | mips `syscall4` and up lack the `$a3` output |
| `c6044e6` | `base64` decoded-size bound wrong |
| `4465f34` | `aessiv` with empty input |
| `15c1d31` | `std.http` request-body edge cases |
| `bf93660` | `stack_protector` is not part of the cache key: stale objects after toggling it |
| `a81a808` | `@shrExact` does not emit `shr_exact` under safety |
| `7c793c2` | `checkAllAllocationFailures` / `NondeterministicMemoryUsage` (see std-testing.md for a workaround that was compiled and run) |
| `12caf4e` | `powWithEncodedExponent` length leak (see above) |
| `Io.Event.waitTimeout` spurious wakeups (#36912) | open pull request, not merged anywhere |
| #37131 | issue open, fix PR open and unmerged when the inventory was taken (2026-10-18): signed to narrower unsigned `@intCast` is `trunc nsw` (reproduced here, see above) |
