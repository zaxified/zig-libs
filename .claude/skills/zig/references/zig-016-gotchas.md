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

### Debug builds are for debugging, not for verification

The default Debug backend is the self-hosted one; Release modes use LLVM. Under valgrind a
self-hosted build produced tens of thousands of `DWARF2 reader` warnings and wrong line
numbers for most frames. More generally, anything that measures or verifies (valgrind,
timing, constant-time checks, fuzzing throughput) should run on ReleaseSafe or ReleaseFast:
the binary under test should be the one that ships.

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

### Deleting `.zig-cache/o` wedges the build runner

After deleting only the outputs (`.zig-cache/o/`), every `zig build`, even `zig build -h`,
fails with `failed to spawn build runner .zig-cache/o/<hash>/build: FileNotFound`, and
rerunning does not help: the manifests in `.zig-cache/h/` still point at the deleted
outputs. Tell the user; the fix is to remove the flat manifest files at the top level of
`.zig-cache/h/` (their outputs are already gone, so nothing extra is rebuilt), then run
`zig build --list-steps`. Do not work around it with a private `--cache-dir`, which costs
a second full cache on a disk that just ran out.
