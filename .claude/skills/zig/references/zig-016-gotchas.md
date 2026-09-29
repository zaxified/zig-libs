# Zig 0.16.0 Gotchas (found in production code)

Traps that compile cleanly and look idiomatic, each found in real code on Zig 0.16.0 and
confirmed against the std source or by measurement. Most produce no error at all: the
program runs and is wrong, slow, or leaks.

## Language

### `a, b = .{ b, a }` is not a swap

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

### `@intFromFloat` out of range is illegal behaviour

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

## std.Io

### Cancellation is erased at the `Io.Reader` boundary

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

Its inline asm lists `rsi` (aarch64: `x1`) as output, input and clobber. clang rejects the
same shape in C; Zig passes it to LLVM, and under register pressure the asm is entered with
a stale `rsi`, crashing at address `0xaa` in ReleaseSafe. Whether it bites depends on the
surrounding code, so a small test program does not reproduce it. Tracked upstream as
Codeberg ziglang/zig issue 35724.

Code that drives fibers directly: use a `noinline` copy of `contextSwitch` whose clobber list
omits the input register, with a comment naming the issue so it can be removed on the next
Zig release.

## Testing and fuzzing

### Fuzz corpus entries lose their first four bytes

`std.testing.Smith.slice` reads a 4-byte little-endian length from the input before the
bytes. A raw seed passed as `.corpus = &.{"GET / HTTP/1.1..."}` loses its first four bytes
to that length, so the seed never reaches the code it was written for.

- Prefix every seed with its length (a small helper that builds the encoded entry).
- Call `slice` first in the harness.
- Add a test that decodes each seed through `Smith{ .in = entry }` and asserts it reaches
  the intended branch.

The 0.16 fuzzer explores raw bytes poorly; give harnesses a structured half built from
`smith.value(T)` and friends. See [std.testing](std-testing.md).

### Two backends: self-hosted for the edit loop, LLVM for test runs

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

### Without libc, `@memset` is a byte loop

In a binary that does not link libc, `@memset` (and `std.crypto.secureZero`, which is a
`@memset` over volatile memory, byte-wise even with libc) calls `compiler_rt.memset`, which
writes one byte at a time: about 18x slower than glibc. In ReleaseSmall `memcpy`/`memmove`
are byte loops too; `memcmp`/`bcmp` always are. Small calls barely matter. It only bites
for large blocks on a hot path (measured: zeroing 116 KiB took 33.7 us instead of 1.8 us).

```zig
// Zero a 32-byte-aligned buffer whose length is a multiple of 32.
const V = @Vector(32, u8);
const words: [*]volatile V = @ptrCast(@alignCast(buf.ptr));
for (0..buf.len / 32) |k| words[k] = @splat(0);
```

Both `volatile`s matter: one keeps the stores from being removed as dead, the other stops
LLVM from recognising the loop as a memset idiom and turning it back into the slow call.

## Security

### `std.crypto` leaves key schedules on the stack

After a TLS 1.3 handshake, the AES round keys (176-byte `AesEncryptCtx`, round key 0 is
the raw key) were found at about ten places on the dead stack below the caller.
`secureZero` on your own structs only clears the copies you own; it cannot reach frames
inside `std.crypto.aead.*`. "The key does not outlive the connection" is only true if the
stack itself is scrubbed (for example `MADV_DONTNEED` on a fiber stack before reuse). A
pooled OS thread keeps whatever was last written there.

## Build system

### `build.zig.zon` facts

- `.fingerprint`: the upper 32 bits are the CRC-32 of the package name; the lower 32 are
  an arbitrary id.
- Unknown fields are ignored, at top level and inside dependency entries. A field ignored
  today can collide with a real one tomorrow, so prefix tool-specific fields
  (`.mytool_upstream`, not `.upstream`).
- A dependency URL must carry an explicit ref and the entry must have a `.hash`; a floating
  branch is rejected. Updates only arrive through a deliberate `zig fetch --save`.
- `zig build --fork=/path/to/checkout` overrides a package throughout the dependency tree
  without editing the manifest, which is safer than temporarily switching the pin to `.path`.

### The self-hosted x86_64 backend cannot encode what the target CPU lacks

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
const pclmul_emittable = builtin.cpu.arch == .x86_64 and
    (builtin.zig_backend != .stage2_x86_64 or
        std.Target.x86.featureSetHas(builtin.cpu.features, .pclmul));

fn cpuHasPclmul() bool {
    if (builtin.cpu.arch != .x86_64) return false;
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

### Optimize modes are renamed after 0.16 (0.17-dev only, not in 0.16.0)

On the 0.17 development branch `std.builtin.OptimizeMode` is `.debug`, `.safe`, `.fast`,
`.small`, and the build option reads `-Doptimize=safe`. A `build.zig` that compares against
`.Debug` or `.ReleaseSafe`, and every script that passes `-Doptimize=ReleaseSafe`, needs
updating on the upgrade.

### Deleting `.zig-cache/o` wedges the build runner

After deleting only the outputs (`.zig-cache/o/`), every `zig build`, even `zig build -h`,
fails with `failed to spawn build runner .zig-cache/o/<hash>/build: FileNotFound`, and
rerunning does not help: the manifests in `.zig-cache/h/` still point at the deleted
outputs. Tell the user; the fix is to remove the flat manifest files at the top level of
`.zig-cache/h/` (their outputs are already gone, so nothing extra is rebuilt), then run
`zig build --list-steps`. Do not work around it with a private `--cache-dir`, which costs
a second full cache on a disk that just ran out.
