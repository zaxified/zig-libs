---
name: zig-0.17
description: "Zig 0.17.0 patterns, checked against the released standard library. Use when writing, reviewing, or debugging Zig code for Zig 0.17.x (zig version / minimum_zig_version in build.zig.zon; a 0.16 project uses the zig skill instead), build.zig and build.zig.zon files, or comptime metaprogramming. Covers the 0.17 changes: array ** removed (@splat), errdefer capture and @cImport removed (translate-c package), @intFromEnum to @backingInt, struct-of-arrays @typeInfo (field_names, field_types), @bitCast on extern structs, @hasDecl pub-only, std.builtin to std.lang with .debug/.safe/.fast/.small, SafeAllocator and BufferFirstAllocator, Allocator.print and mem.print, mem.find, zon.parse with an arena, b.args to addPassthruArgs, custom build steps removed (host tool + Run step), array/vector @bitCast as logical little-endian bits, the #37131 signed-to-narrower-unsigned @intCast/math.cast miscompile in optimized builds, the configurer/maker build split with its cached configuration (undeclared configure-time reads go stale: dependOnDirectoryContents, poisonCache), optimize-mode spellings on the CLI, incremental builds with the self-hosted backend, and zig-pkg/. Also prevents older patterns from training data: the std.Io instance threaded through files, sockets, clocks and locks (std.fs to std.Io.Dir/File, std.net to std.Io.net, std.time timestamps and Timer to std.Io.Clock, std.Thread.Mutex/Condition/Pool to std.Io.Mutex/Condition/Group, std.crypto.random to io.randomSecure), main(init: std.process.Init), build system APIs (root_module, Compile methods to Module methods), buffered Reader/Writer with flush, removed async/await and usingnamespace; plus gotchas found in production code."
license: MIT
compatibility:
  - claude-code
  - opencode
  - codex
metadata:
  version: "0.17.0"
  language: "zig"
  category: "programming-language"
---

# Zig Language Reference (v0.17.0)

Zig evolves rapidly. Training data contains outdated patterns that cause compilation errors. This skill documents breaking changes and correct modern patterns.

**Version coverage:** 0.17.0 (current) with migration notes from 0.16, 0.15.x and 0.14.x.

## Design Principles

### Type-First Development
Define types and function signatures before implementation. Let the compiler guide completeness:
1. Define data structures (structs, unions, error sets)
2. Define function signatures (parameters, return types, error unions)
3. Implement to satisfy types
4. Validate at compile-time

### Make Illegal States Unrepresentable
Use Zig's type system to prevent invalid states at compile time:
- **Tagged unions** over structs with optional fields — prevent impossible state combinations
- **Explicit error sets** over `anyerror` — document exactly which failures can occur
- **Distinct types** via `enum(u64) { _ }` — prevent mixing up IDs (user_id vs order_id)
- **Comptime validation** with `@compileError()` — catch invalid configurations at build time

### Module Structure
Larger cohesive files are idiomatic in Zig. Keep related code together — tests alongside implementation, comptime generics at file scope, visibility controlled by `pub`. Split files only for genuinely separate concerns. The std library demonstrates this with files like `std/mem.zig` containing thousands of cohesive lines.

### Memory Ownership
- Pass allocators explicitly — never use global state for allocation
- Use `defer` immediately after acquiring a resource — cleanup next to acquisition
- Name allocators by contract: `gpa` (caller must free), `arena` (bulk-free at boundary), `scratch` (never escapes)
- Prefer `const` over `var` — immutability signals intent and enables optimizations
- Prefer slices over raw pointers — bounds safety

## Critical: Zig 0.17.0 Changes

Everything below the 0.17 sections still describes 0.17.0 unless it is marked as old. Check
the project's toolchain first (`zig version`, `minimum_zig_version` in `build.zig.zon`): a
0.16 project needs the 0.16 skill, not these spellings.

### Removed syntax and builtins
```zig
// WRONG (0.17) — array repetition `**` is removed (parse error)
var buf = [_]u8{0} ** 64;
// CORRECT
var buf: [64]u8 = @splat(0);

// WRONG (0.17) — errdefer capture is removed
errdefer |err| log.err("failed: {t}", .{err});
// CORRECT — catch in a wrapper
fn run(job: Job) void {
    runInner(job) catch |err| log.err("failed: {t}", .{err});
}

// WRONG (0.17) — void{} and i0 are removed
const v = void{};
// CORRECT
const v = {};       // i0 → u0
```

Replacing `**` mechanically (all forms below compiled and ran on 0.17.0):
- `[_]T{v} ** N` → `@as([N]T, @splat(v))`; where the result type is known (declaration with a
  type, field, fixed-size parameter) plain `@splat(v)` is enough. Concatenation still works:
  `@as([4]u8, @splat(1)) ++ [_]u8{9}`.
- One repeated byte (`"x" ** 100`) needs no helper: `comptime &@as([100:0]u8, @splat('x'))` is a
  `*const [100:0]u8` (sentinel kept, a valid `++` operand, coerces to `[]const u8`) that points
  at a static constant, so a slice of it returned from a runtime scope does not dangle (probe in
  Debug and ReleaseFast, with a stack clobber between the call and the read). At container level
  drop the `comptime` (error: "redundant comptime keyword in already comptime scope").
- String repetition (`"ab" ** 3`, `line ** n` with a comptime `line`) has no builtin: use a
  comptime helper, and **declare it `inline fn`**. Assign the result from a `comptime` block and
  return a pointer to that constant, and give the loop an eval quota that scales with the work —
  `n * (s.len + 4) + 1000` (one migration saw `evaluation exceeded 3002 backwards branches` with
  `n * 2 + 1000` at n = 998, which an isolated probe did not reproduce, so do not tune the quota
  down):
  ```zig
  inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
      const rep_result = comptime blk: {
          @setEvalBranchQuota(n * (s.len + 4) + 1000);
          var buf: [s.len * n:0]u8 = undefined;
          for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
          const rep_final = buf;
          break :blk rep_final;
      };
      return &rep_result;
  }
  ```
  Write it as `const r = comptime blk: { ...; break :blk f; }; return &r;`, not as
  `comptime { ...; return &f; }`: the latter fails ("function called at runtime cannot return
  value at comptime") when the helper is called from a runtime scope (probe-verified in a
  migration codemod; the first form works from both).
  **Without `inline` it is silently wrong.** A plain `fn` called from a runtime scope (a test
  body, a function with a comptime parameter that is not itself evaluated at comptime) makes
  `"x" ++ s ++ strRepeat("ab", 3) ++ "y"` a runtime concatenation into a stack temporary, and a
  slice of it returned or stored dangles: no error, garbage bytes (found in a real module in
  Debug and ReleaseFast; the minimal probe below reproduces it on 0.17.0 in ReleaseFast, and in
  Debug only when the stack happens to be overwritten). Moving the helper's result into a
  struct-decl static does not help; only `inline` makes the call's result comptime-known. The
  same applies to any helper that returns `*const [N]u8` and is used as an operand of `++`.
  The plain `fn` also has a loud symptom: `inline for (msgs)` over a local
  `const msgs = [_][]const u8{ "", strRepeat("a", 100) }` fails with `unable to evaluate comptime
  expression` / `types must be comptime-known` at the first use of `msg.len` as an array length
  (the migration fixed it with `comptime` on the array declaration). With `inline fn` the same
  code compiled with and without that `comptime` (ten probe shapes in Debug, two of them also in ReleaseSafe; the exact shape above in Debug, ReleaseSafe and ReleaseFast).
  ```zig
  noinline fn wrong() []const u8 { return "x" ++ strRepeatPlainFn("ab", 3) ++ "y"; } // WRONG: dangles
  noinline fn right() []const u8 { return "x" ++ strRepeat("ab", 3) ++ "y"; }        // inline fn
  // ReleaseFast: after any call that uses the stack, wrong() reads "\x00\x00..." and right()
  // still reads "xabababy".
  ```
- A codemod that rewrites `** N` to `@as([N]u8, @splat(x))` is wrong for non-byte element types
  (seen on an array of structs): grep the result for `\[[0-9]+\]u8, @splat\([a-z]` and check
  each hit's real element type.
- Multi-element arrays (`[_]T{ a, b } ** N`): the same shape without the sentinel,
  `fn arrRepeat(comptime T: type, comptime unit: []const T, comptime n: usize) [unit.len * n]T`
  (a plain function with `@setEvalBranchQuota` and a `@memcpy` loop).
- Watch for `@typeInfo(X).@"enum".fields.len` used as the length: it is now
  `.field_names.len`, e.g. `var seen: [@typeInfo(E).@"enum".field_names.len]bool = @splat(false);`
  (a mechanical rewrite that wraps `@splat(false)` in `@as([@typeInfo(E)]bool, …)` yields invalid code).

`@cImport` is removed: translate C headers with the `translate-c` package
(add it with `zig fetch --save` on a pinned ref — a release tag or commit of
https://codeberg.org/ziglang/translate-c, not the moving default branch — then
`@import("translate_c").Translator` in `build.zig`).
Fetching needs the network: ask the user before adding the dependency. Without a dependency:
`b.addTranslateC(.{ .root_source_file = b.path("src/c.h"), .target = target, .optimize = optimize })`
still exists in the 0.17.0 std (`Build.zig`, `Build/Step/TranslateC.zig`; `link_libc` defaults to
true; `.createModule()` gives the module to import) and the toolchain ships the translator
(`lib/compiler/translate-c`). The release notes call it deprecated in favour of the package
(more options, own release cadence); the std source carries no deprecation marker and the
compiler stays silent about it. For a plain header with no extra options it is the route that needs
no network. Compiled and run on 0.17.0 for this skill (a header with a `static inline` function
and a `#define`, imported through `.createModule()`); a migration used it for `sqlite3.h`, where
the first use compiled the translator (about a minute).
`GlobalLinkage` lost `.internal` and `.link_once` (use `.weak`, or simply do not `@export`).

### Enum ↔ integer: `@backingInt` / `@fromBackingInt`
```zig
const Color = enum(u8) { red, green };
// WRONG (0.17) — deprecated (zig fmt rewrites them)
const n = @intFromEnum(c);
// CORRECT
const n = @backingInt(c);                        // also: packed structs/unions with an explicit backing int, tagged unions (the tag)
const c: Color = @fromBackingInt(@intCast(i));   // argument must be exactly the backing type
```
New: `@divCeil(a, b)` (rounds toward +inf) replaces `std.math.divCeil(...) catch unreachable`.

### `@typeInfo` is struct-of-arrays
```zig
// WRONG (0.17) — no .fields / .decls arrays of structs
inline for (@typeInfo(T).@"struct".fields) |f| use(f.name, f.type);

// CORRECT
const info = @typeInfo(T).@"struct";
inline for (info.field_names, info.field_types, 0..) |name, FieldT, i| {
    const attrs = info.field_attrs[i];   // .@"comptime", .@"align", .default_value_ptr
    use(name, FieldT, attrs);
}
```
Cheapest rewrite of an old loop body: keep the body and rebuild the old record per iteration,
`inline for (info.field_names, info.field_types) |f_name, f_type| { const f = .{ .name = f_name, .type = f_type }; ... }`,
or write one private `structFields(T)` shim that returns name/type/attrs and call it where
`.fields` was (both used in migrations of cbor/yaml/protobuf/validation modules; compiled and
tested there, not re-run for this skill).

The same shape everywhere: enum `field_names`/`field_values`/`mode` (was `is_exhaustive`),
fn `param_types`/`param_attrs`/`attrs.@"callconv"`/`attrs.varargs` (`param_types` elements are
`?type`: `null` is an `anytype` parameter, so `Fn.params[i].type` becomes `param_types[i]` with the
same optional type), pointer
`attrs.@"const"`/`@"align"`/`@"volatile"`/`@"allowzero"`/`@"addrspace"`, `decl_names` (plain
strings, so the `.name` of a declaration entry goes) instead of `decls`, `error_set.error_names`. `std.meta.fields` is a compile error; `fieldNames`,
`fieldInfo`, `fieldTypes` are deprecated. `@Type` is gone (since 0.16): build types with `@Int`,
`@Struct`, `@Union`, `@Enum`, `@Pointer`, `@Fn`, `@Tuple`.

### Silent changes (compile, behave differently)
- **`@bitCast` reinterprets logical bits.** Arrays and vectors now behave as little-endian on
  every target. A cast of an `extern struct`/`extern union` — from it or to it — is a
  **compile error**: for type punning use `@ptrCast` (`const p: *align(1) const u16 = @ptrCast(&bytes);`),
  an extern union, or, for bytes into a C struct,
  `std.mem.bytesToValue(sockaddr.in, bytes[0..@sizeOf(sockaddr.in)])` (a copy; `bytesAsValue`
  gives a pointer), where `sockaddr` is `std.os.linux.sockaddr` in pure-Linux code without libc
  (`std.posix.sockaddr` is libc's type when libc is linked, the Linux one otherwise).
  A `[N]u8` ↔ integer `@bitCast` that meant "the bytes as they lie in memory" (a network-order
  address in a `u32` field such as `sockaddr.in.addr`, a kernel-ABI word) now is a logical
  little-endian cast and changes value on a big-endian target. The memory-order spelling,
  same result as 0.16 on every target: `std.mem.bytesToValue(u32, &bytes)` /
  `std.mem.toBytes(x)` (a `[4]u8` copy); when the byte order is a protocol fact rather than
  "whatever memory has", `std.mem.readInt(u32, &bytes, .big)` / `std.mem.writeInt(u32, &bytes, x, .big)`.
  Code that byte-swapped on big-endian *before* an array↔vector/integer `@bitCast` (to make the
  cast see memory order) now swaps twice: remove the swap. Run-verified in a migration on
  s390x under qemu (ReleaseSafe, module test suites): a ChaCha20-Poly1305 implementation passed
  27 of 55 tests with the old big-endian swap and 49 of 55 after dropping it (the same count as
  on 0.16), and a sealed-box module went from 3 failures to the 0.16 result (38 of 43) the same
  way. The rule matches the language reference (earlier elements in less significant bits on
  every target); a mips probe agreed. Test on a big-endian target, e.g. s390x under qemu.
- **A word that must appear in big-endian order inside a `[N]u8`** (a TLS/AEAD nonce, a
  sequence number in an AAD) is `@as([8]u8, @bitCast(@byteSwap(x)))` with an **unconditional**
  swap: the array side of the cast is little-endian on every target, so a
  *conditional* swap (swap only on a little-endian host) is right on one endianness and wrong on
  the other, and a bare `@bitCast(x)` gives little-endian bytes everywhere. `std.crypto.tls.Client` does exactly this
  (`crypto/tls/Client.zig:374,414,790,1103`: `pad ++ @as([8]u8, @bitCast(@byteSwap(seq)))`). Six
  nonce sites in one migration needed this fix. `std.mem.writeInt(u64, &out, x, .big)` says the
  same thing without the cast.
  ```zig
  // WRONG (0.17): conditional swap keyed on the host, or a bare cast of a "big()" helper
  const be: [8]u8 = @bitCast(if (builtin.cpu.arch.endian() == .little) @byteSwap(x) else x);
  // RIGHT: logical little-endian cast of the byte-swapped value, on every target
  const be: [8]u8 = @bitCast(@byteSwap(x));
  ```
- **`@bitCast` of a `@Vector(n, bool)` to an integer: lane i is bit i on every target.** 0.16
  big-endian code needed `@bitReverse` after it (a match-mask extraction); remove it. Checked at
  comptime on x86_64 and mips-linux-musl with a negative control, and a mask-extraction routine
  ran correctly on s390x under qemu (migration observations).
- **`@intCast` / `std.math.cast` from a signed integer to a narrower *unsigned* one is
  miscompiled in optimized builds (open, see #37131; not fixed in 0.17.0).** The
  frontend emits LLVM `trunc nsw` (it should be `nuw`), so every value in the upper half of
  the destination range (`0x8000_0000..0xFFFF_FFFF` for `u32`) is poison and LLVM may delete
  any check that depends on it. Debug is unaffected, so the tests pass there. Whether an
  optimized build exploits it depends on inlining and layout: the IR is `trunc nsw` in every
  mode, and a test that does not fail proves nothing. Reproduced on 0.17.0 with
  `noinline fn f(eb: i64) u32 { if (eb < 0 or eb > 0xFFFF_FFFF) return 1; const v: u32 = @intCast(eb); if (v > 0x7FFF_FFFF) return 2; return 0; }`
  called with `eb = 0xFFFF_FFFF` passed through `std.mem.doNotOptimizeAway(&y)`: 2 in Debug,
  0 in ReleaseSafe and ReleaseFast (a plain `var x: i64 = 0xFFFF_FFFF; _ = &x;` argument did not
  fail; an `export fn` build shows the branch folded away in the optimized IR). A real case:
  an SNMP anti-replay range check on a decoded engine-boots value was folded away.
  **Keep the range check in every spelling:** `@intCast` of a negative `i64` to `u64` is
  illegal behaviour (a panic in safe builds, a wrong value in ReleaseFast), so the cast to the
  same-width unsigned type needs its own check. Safe spelling, checked in Debug, ReleaseSafe
  and ReleaseFast: `const w = std.math.cast(u64, x) orelse return error.OutOfRange; const v = std.math.cast(u32, w) orelse return error.OutOfRange;`
  (or `if (x < 0 or x > std.math.maxInt(u32)) return error.OutOfRange;` first, then
  `const w: u64 = @intCast(x); const v: u32 = @intCast(w);`, or
  `@truncate(@as(u64, @bitCast(x)))` after the same check). Unsigned to narrower unsigned,
  and signed to narrower signed, are fine. Details, the cast-shape table and the places std
  itself is hit: zig-gotchas.md.
- **`@hasDecl` sees only `pub` declarations**, also from inside the same file. This also hits
  option declarations a *consumer* supplies and a library probes (`@hasDecl(Root, "my_options")`,
  optional methods on a user-supplied type): without `pub` the probe is silently `false` and
  the library takes its default path. `rg '@hasDecl'` over the library lists the probes; make
  the declarations the probe looks for `pub` in tests and docs (a non-`pub` method that is
  then *called* is a compile error instead).
- **`std.mem.containsAtLeastScalar(T, list, element, minimum)`** — `element` and `minimum`
  swapped places; old calls with an integer element still compile.
- **`std.testing.allocator` is a `SafeAllocator`**, fresh for every test: it hands a large
  allocation and every emptied 8 KiB bucket back to `page_allocator`, so a loop of
  alloc/free pairs stays flat (probe on 0.17.0, 2 000 000 x 64 B in one test: RSS 700 -> 708 KiB
  in ReleaseSafe, 4524 -> 4584 KiB in Debug). Slots inside a bucket are never reused, though, so
  long-lived small allocations interleaved with short-lived ones pin whole buckets (same probe,
  1 in 64 kept: 195 KiB live, RSS 748 -> 14988 KiB). It checks writes after
  free in every mode, records allocation stack traces only in Debug, and a leak fails the test
  in every mode, ReleaseFast included. In a loop that runs thousands of seeds/iterations in one
  test (fuzz and property drivers) giving each iteration its own allocator is still useful, for
  leak attribution per iteration and to drop pinned buckets between iterations:
  `var sa = std.heap.SafeAllocator.init(gpa, .{ .stack_trace_frames = 0 }); defer _ = sa.deinitLog(false);`
  (`deinit()` returns the leak count and logs; `deinitLog(false)` is silent — `SafeAllocator.zig`
  `init`/`deinit`/`deinitLog`), and turn a non-zero leak count into the iteration's failure.
  `SafeAllocator` also resizes in place on `remap`, so a `std.testing.FailingAllocator` test
  that pins `fail_index` can see fewer allocations than in 0.16 (seen in a migration: a
  `fail_index = 2` was never reached because `toOwnedSlice` no longer allocated a second
  time; `1` hit the intended allocation): re-derive the index from `alloc_index` of a clean
  run instead of copying the old number.

### Renamed std
| 0.16 | 0.17.0 |
|---|---|
| `std.builtin` | `std.lang` (`std.builtin` is a deprecated alias) |
| `std.builtin.OptimizeMode` `.Debug/.ReleaseSafe/.ReleaseFast/.ReleaseSmall` | `std.lang.Optimize` `.debug/.safe/.fast/.small` — `==` against the old names no longer compiles |
| `std.debug.runtime_safety` | `@import("builtin").mode.runtimeSafety()` |
| `std.heap.DebugAllocator`, `GeneralPurposeAllocator` | `std.heap.SafeAllocator` (`.init(backing, .{})`, `deinit()` returns the leak count) |
| `std.heap.stackFallback(n, gpa)` | `std.heap.BufferFirstAllocator.init(&buf, gpa)` |
| `std.fmt.allocPrint(a, f, args)` | `a.print(f, args)` |
| `std.fmt.bufPrint(buf, f, args)` | `std.mem.print(buf, f, args)` |
| `std.mem.indexOf*`, `lastIndexOf*` | `std.mem.find*`, `findLast`, `findScalarLast` |
| `std.fs.path`, `std.fs.max_path_bytes` | `std.Io.Dir.path`, `std.Io.Dir.max_path_bytes` |
| `list.getLast()` / `getLastOrNull()` | `list.last().?` / `list.last()`; new `lastPtr()` |
| `std.bit_set.IntegerBitSet`/`ArrayBitSet`/`StaticBitSet`/`DynamicBitSetUnmanaged` | `Integer`/`Array`/`Static`/`Dynamic`; `.initEmpty()`/`.initFull()` → `.empty`/`.full` (also `std.EnumSet`; `Dynamic.initEmpty(gpa, n)` is unchanged) |
| `std.ArrayListUnmanaged`, `std.AutoArrayHashMapUnmanaged` | `std.ArrayList`, `std.array_hash_map.Auto` |
| `std.zon.parse.fromSliceAlloc(T, gpa, src, &diag, .{})` + `free` | `std.zon.parse.fromSlice(T, .{ .gpa, .arena, .source, .diagnostics })` — result lives in the arena |
| `uri.getHost(&buf)` | `std.Io.net.HostName.fromUri(uri, &buf)` (validates RFC 1123) |
| `std.tar.pipeToFileSystem` | `std.tar.extract` |
| `std.gpu` | `std.spirv` |

**Not moved** (probed on 0.17.0, a common wrong assumption): `@import("builtin").cpu`, `.os`,
`.abi` and `.object_format` still exist next to `.target.cpu` / `.target.os` / `.target.abi` /
`.target.ofmt`, and `@typeInfo(fn).@"fn".return_type` is unchanged. Only the enum members of
`builtin.mode` changed (`.Debug` → `.debug`); a bulk search-and-replace of `builtin.cpu`/`builtin.os`
is wasted work.

Removed or changed without a rename in the table above (each checked in the 0.17.0 std):

| 0.16 | 0.17.0 |
|---|---|
| `std.ascii.indexOfIgnoreCase`, `indexOfIgnoreCasePos`, `indexOfIgnoreCasePosLinear` | `findIgnoreCase`, `findIgnoreCasePos`, `findIgnoreCasePosLinear` (`ascii.zig`). Removed outright, not deprecated: a compile error, although the `std.mem.indexOf*` names still compile as deprecated aliases |
| `std.fmt.bufPrintZ(buf, f, args)` | `std.mem.printSentinel(buf, f, args, 0)` (`std.fmt.bufPrintSentinel` still exists but is deprecated) |
| `allocator.dupeZ(u8, s)` | `allocator.dupeSentinel(u8, s, 0)` (`mem/Allocator.zig` `dupeSentinel`) |
| `std.meta.Int(.unsigned, n)` | builtin `@Int(.unsigned, n)` |
| `std.meta.fields(T)` | compile error: `@typeInfo(T)` (`field_names`, `field_types`, …) |
| `std.meta.fieldNames(T)` | deprecated; returns a slice `[]const [:0]const u8` (not an array), so `a ++ b` of two results needs `comptime`; prefer `@typeInfo(T).@"struct".field_names` |
| `std.meta.declarations(T)` (items with `.name`) | returns the names themselves, `[]const [:0]const u8` |
| `std.builtin.Type.StructField.Attributes` | `std.lang.Type.Struct.FieldAttributes` (`Union.FieldAttributes` likewise) |
| `@typeInfo(E).error_set` (`?[]const Error`, `.name` per error) | `.error_set.error_names`: `?[]const [:0]const u8`, plain strings |
| `os.linux.wait4`/`waitpid(pid, status: *u32, …)` | `status: *i32` — keep a `u32` field and `@bitCast` at the call boundary |
| `std.os.linux.SYS.fstatat64` on x86_64 (`.X64`) | `.newfstatat` (262, `os/linux/syscalls.zig`); the name differs per architecture (e.g. arm/x86 `fstatat64`, aarch64/riscv64 `newfstatat`) — code that spans targets selects with `@hasField(std.os.linux.SYS, "newfstatat")` |
| `std.elf.Elf64_Phdr` (`p_type`, `p_offset`, `p_vaddr`, …) | `std.elf.Elf64.Phdr` / `std.elf.ElfN.Phdr` with unprefixed fields `type` (enum `std.elf.PT`: `switch (ph.type) { .LOAD, .DYNAMIC => … }`), `offset`, `vaddr`, `paddr`, `filesz`, `memsz`, `flags`, `align`; `std.elf.AT.SYSINFO_EHDR` |
| `Io.VTable.netRead` / `netSend` / `netWrite` | one `vtable.operate(userdata, Operation)`; a test double that wraps a real `Io` overrides `operate`, switches on `.net_read` (`operate` also carries `.net_send` and `.net_write`, `Io.zig` `Operation`), and forwards the rest. `netClose` now takes `[]const net.Socket` (`Io.zig` VTable). `NetRead.Error` has `ConnectionTimedOut` and no `Timeout`: a fake `Io` that maps its own `Timeout` must rename it. A wrapper that builds its vtable by copying a base and overriding every entry whose *name* matches a declaration of its own keeps compiling when std folds an entry away, and the override is then never installed: socket reads and writes silently go to the base backend (seen in a uring `Io` after the fold). Make an unmatched override name a compile error (std-io.md, "Wrapping an Io") |

`std.ArrayList` gained a `pointer_stability` field (a debug lock behind `lockPointers()` /
`unlockPointers()`): a hand-written literal `.{ .items = &.{}, .capacity = 0 }` no longer
compiles — use `.empty` or `.initBuffer(&buf)`.

Deprecated names still compile silently (the compiler prints nothing about them), and neither `zig build`, `zig test` nor any
flag lists them (`--help` of both checked). To find them in a project, grep for the left column
of the tables above and for the names the deprecation bullets mention, e.g.
`rg -n 'indexOf|lastIndexOf|allocPrint|bufPrint|ArrayListUnmanaged|std\.builtin|DebugAllocator|\.getLast|@intFromEnum|@enumFromInt' src build.zig`
(a suggestion built from the table — extend it). `zig fmt` 0.17 rewrites `@intFromEnum(x)` to
`@backingInt(x)` and `@enumFromInt(x)` to `@fromBackingInt(@intCast(x))` in every file it
formats (checked on a probe file): format only the files you mean to change, or expect a diff
in every file that contains them (and, in a repository that pins source digests, new digests).

### Build system
```zig
// WRONG (0.17) — build scripts no longer see CLI args
if (b.args) |args| run_cmd.addArgs(args);
// CORRECT
run_cmd.addPassthruArgs();   // forwards `zig build run -- a b c`
```
- `zig build` runs `build.zig` in a separate *configurer* process; a cached *maker* executes the
  graph. The first `zig build` after installing Zig compiles the maker (measured twice: 108 s
  and 115 s; Zig 0.17.0, x86_64 Linux, 8-core machine; once per toolchain and global cache — keep
  `ZIG_GLOBAL_CACHE_DIR` cached in CI; on a developer machine the global cache usually already
  holds the maker from another 0.17 project: a first build of a small project (~4.3k
  lines, Zig 0.17.0, x86_64 Linux) took 5.7 s in total; maker already in the global cache). A script that gives each lane its own
  `ZIG_GLOBAL_CACHE_DIR` pays the maker once per lane. (One exception where separate caches
  help: while 0.16 and 0.17 both fetch packages, see the zig-gotchas.md note on a shared
  global cache.) Later runs skip `build.zig` entirely when the
  configuration key is unchanged (`zig build --help` then took 15 ms, same machine).
- **The configuration is cached, and only declared inputs invalidate it.** The key is the
  `-D`/CLI options, the target and the `build.zig` sources. A `build.zig` that reads a
  directory, a file or an environment variable at configure time keeps the old result after
  that input changes — measured on 0.17.0 with a `build.zig` that counted the entries of a
  directory and read an env var into `b.addOptions()`: adding a file and changing the variable
  were both ignored, silently, and `--cache-poison=disallowed` did not notice (the configurer
  never ran). Declare files and directories with `b.dependOnFileContents` /
  `dependOnDirectoryContents` (or `*Metadata`; the directory form tracks added, removed and
  renamed entries, not their contents, and is not recursive); there is no declaration for environment
  variables — turn them into `-D` options, or call `b.graph.poisonCache()` after reading one
  (configuration then reruns on every invocation). `zig build --cache-poison=poisoned` forces
  one rerun.
- `zig build` rejects (measured, "unrecognized argument"): `--global-cache-dir` (use the
  `ZIG_GLOBAL_CACHE_DIR` environment variable), `--zig-lib-dir` (now `--zig-lib=`, which must
  be the first argument), `--build-runner`, `--verbose-llvm-bc`. New: `--print-configuration`,
  `--cache-poison`, `--listen=-`. `b.cache_root` and `b.graph.global_cache_root` no longer
  exist; a step that needs the local cache directory gets `std.Build.LazyPath.cache_root`.
- `b.build_root` → `b.root` (a `Cache.Path`): use its methods, `b.root.access(io, sub, .{})`,
  `b.root.openDir(io, sub, .{})`, `b.root.openFile(...)` (they join `p.sub_path` themselves).
  `b.root.joinString(gpa, sub)` returns a path that already includes `root_dir`, so passing it
  to `b.root.root_dir.handle` doubles the prefix (`Cache/Path.zig` `joinString` vs `openDir`).
  `LazyPath.getDisplayName()` → `"{f}"`.
- **Custom build steps are gone.** `Step.makeFn`/`Step.init` with a user function no longer
  exist: a `Step` carries a `tag` from the closed `Configuration.Step.Tag` set (`compile`, `run`,
  `fmt`, `write_file`, `check_file`, `options`, …), because the maker executes a serialized
  graph and never calls back into `build.zig`. Anything that was a `makeFn` (repository
  checks, generators, file-walking gates) becomes a **host executable plus a Run step**:
  ```zig
  const gates = b.addExecutable(.{ .name = "gates", .root_module = b.createModule(.{
      .root_source_file = b.path("scripts/gates.zig"),
      .target = b.graph.host,
      .optimize = .safe,
  }) });
  const run = b.addRunArtifact(gates);
  run.addArg("check-changelog");
  run.addPrefixedFileArg("--zig=", b.graph.path(.zig_exe, ""));   // what old code read from `b`
  run.has_side_effects = true;            // never cached: it reads the tree, not declared inputs
  run.setCwd(b.path("."));                // the old make fn ran with the package root as cwd
  b.step("check-changelog", "…").dependOn(&run.step);
  ```
  The tool does all file reads at make time (so they need no `dependOn…Contents`). Data the
  old make fns shared with `build.zig` (module lists, tables) is reachable by making the tool
  import `build.zig` itself as a module (`root_module.addAnonymousImport("build_zig", .{ .root_source_file = b.path("build.zig") })`
  and mark the shared declarations `pub`). A step option like `-Dmodule=x` is forwarded to the
  tool as an argument (`--module=x`). Pass what the old code took from `b` (the `zig` binary,
  the cache directory) as arguments: `b.graph.path(.zig_exe, "")` / `b.graph.path(.local_cache, "")`
  (compiled and run on 0.17.0: the tool receives `--zig=/path/to/zig`, `--cache-dir=./.zig-cache`).
  A child `zig build` started by the tool takes the global cache from `ZIG_GLOBAL_CACHE_DIR`.
- `dependOnDirectoryContents`/`dependOnFileContents` on a path that does not exist fails the
  configuration (`error: configuration failed: FileSystemFailure`, checked): declare the nearest
  existing ancestor directory instead — an added entry then still reruns the configuration —
  and, since the form is not recursive, one declaration per directory you scan.
- Run step args: `addOutputFileArg(name)` → `addOutputFileArg2(name, .{})`, and the same `*Arg2(…,
  .{ .prefix = … })` scheme for artifact, file, directory, output-directory and dep-file args.
- Fmt step `paths`/`exclude_paths` take `b.pathList(&.{ "src", "build.zig" })`.
- Option paths: `addOptionPath` (file), `addOptionPathDirectory`, `addOptionPathUntracked`.
- `b.dependencyLazy(name, args)` returns `error.LazyDependencyNeeded`, so `try` works
  (`lazyDependency` returning `null` is deprecated).
- `b.findProgram` poisons the configure cache (configuration is re-run every time); prefer
  `b.findProgramLazy` (a `LazyPath`, searched only when a step needs it). Declare what
  configuration reads with `b.dependOnFileContents` / `dependOnDirectoryContents`.
- Fetched packages land in `zig-pkg/` in the project (add it to `.gitignore`); `--pkg-path` /
  `ZIG_LOCAL_PKG_DIR` move it; `zig build --fork=<path>` overrides a dependency for one build.
- Overriding the build runner is gone (`--build-runner`); IDEs use `zig build --listen=-`
  (Build Server Protocol). **ZLS does not work with 0.17.0** — expect no editor diagnostics.

### Optimize modes and backends
- **Both spellings work in 0.17, only the old ones in 0.16:** `-OReleaseSafe` / `-Osafe` for
  `zig test`/`build-exe`, `-Doptimize=ReleaseSafe` / `-Doptimize=safe` for `zig build`. A
  script shared by 0.16 and 0.17 toolchains keeps the old names. Exception: `--release=`
  accepts only the new names (`--release=ReleaseSafe` fails). Measured on 0.17.0 with
  `zig test -OReleaseSafe`, `zig build run -Doptimize=ReleaseSafe` and `--release=…`;
  0.16.0 rejects `-Osafe` ("unrecognized optimization mode"). In code, compare against
  `.debug`/`.safe`/`.fast`/`.small`.
- `builtin.mode` prints as `debug`, `safe`, … (`{t}`).
- Debug on x86_64 Linux still uses the self-hosted backend; release modes use LLVM;
  `.use_llvm = true` on a compile step, or `-fllvm`, forces LLVM in Debug (unchanged).
- `zig test` / `zig build-exe` reject `-fformatted-panics` / `-fno-formatted-panics`
  ("unrecognized parameter", measured).

### Moving a 0.16 project
1. Pin the toolchain (`minimum_zig_version = "0.17.0"`, CI) and cache the global cache in CI.
   Tell the user before they switch their toolchain: **ZLS does not work with 0.17.0**, so an
   editor on the project (VS Code, Neovim, …) loses diagnostics and completion until a ZLS
   release supports it; `zig build` is the error source meanwhile (see Tooling > ZLS).
2. Parse first: `zig ast-check` every file — array `**`, `errdefer |e|`, `void{}`, `@cImport`
   stop at the parser.
3. `zig fmt` rewrites `@intFromEnum`/`@enumFromInt`; the rest is by hand: struct-of-arrays
   `@typeInfo`, `@bitCast` into extern structs, optimize-mode comparisons (`builtin.mode ==
   .Debug` → `.debug`; `builtin.cpu`/`.os` need no change), `b.args`, `b.build_root`, custom
   build steps (host tool + Run step), configure-time I/O (declare it), bit_set and zon renames.
4. Audit what still compiles: every `@bitCast` of an array/vector, every `@hasDecl` on a
   private declaration, `containsAtLeastScalar` calls. Deprecated names compile silently and
   no flag lists them: grep for the left column of the "Renamed std" table (a codemod for the
   common ones is below). A `@bitCast`
   between `[N]u8` and an integer that meant "the bytes as they lie in memory" is now a
   logical little-endian cast; replace it by `std.mem.bytesToValue`/`toBytes` (or
   `readInt`/`writeInt` with an explicit endianness) — see "Silent changes".
   Also every signed-to-narrower-unsigned `@intCast`/`std.math.cast` (see "Silent changes",
   #37131): the tests pass in Debug and fail, or silently pass a missing check, in ReleaseSafe/
   ReleaseFast, so run the suite in an optimized mode too.
   A hot `[N]u8` <-> wider-lane vector or >= 16-byte integer `@bitCast` (not `[4]u8`<->`u32` / `[8]u8`<->`u64`, a single load) also became a byte loop: route it through
   `@Vector(N, u8)` (see zig-gotchas.md, "byte array and wider lanes").
5. Re-measure: constant-time checks and benchmarks (LLVM 22); anything that pins source text
   or a compiler-output digest (ctgrind contexts, hashes of sources) needs regenerating after
   any source change, including the `zig fmt` rewrites. Do not leave the self-hosted backend in
   a test, valgrind or fuzz lane.

Can land on 0.16 first, working on both: `**` → `@splat`, `@bitCast` into extern structs →
`@ptrCast`/`bytesToValue`, array `@bitCast` for memory order → `bytesToValue`/`readInt`,
dropping `std.meta.fields`, `ArrayList` literals → `.empty`. Not
before the switch: removing `try` from `X25519.KeyPair.generateDeterministic` (0.16 still
returns an error union).

Mechanical rewrite of the deprecated-call churn (a migration had about 300 sites, 146 of them
`allocPrint`); the regexes were applied with `sed -E` and each result was checked by a build and
the tests, and the patterns were re-run here on a sample file (every line rewritten as shown):
```bash
# \b is GNU sed (BSD/macOS sed needs another word-boundary spelling). The `fmt.bufPrint ->
# mem.print` rule needs a name `mem` in scope: in a file that only has `const fmt = std.fmt;`
# the result fails to compile, loudly; add `const mem = std.mem;` there.
# allocPrint: the first argument is an identifier, a field access or a no-arg call
s/std\.fmt\.allocPrint\(([A-Za-z_][A-Za-z0-9_.]*(\(\))?),[ ]?/\1.print(/g
s/\bfmt\.bufPrint\(/mem.print(/g
# anchor the mem renames on the `mem.` prefix so a project's own `indexOf` stays alone;
# note findScalarLast, not findLastScalar
s/\bmem\.lastIndexOfScalar\(/mem.findScalarLast(/g
s/\bmem\.lastIndexOf(Any|None|Linear)?\(/mem.findLast\1(/g
s/\bmem\.indexOf(Scalar|ScalarPos|Any|AnyPos|Pos|None|NonePos|PosLinear)?\(/mem.find\1(/g
```
Grep for `allocPrint|bufPrint|indexOf` afterwards for what the patterns miss (`indexOfDiff`,
`indexOfSentinel`, `indexOfMin`... also became `find*`; check each new name exists in `mem.zig`). `dupeZ(u8, X)` → `dupeSentinel(u8, X, 0)`
by a `[^)]*` regex breaks a call whose `X` contains a call (`map.get("A") orelse "b"` puts the
`, 0` inside `get(...)`): it fails to compile, loudly; fix those by hand.

### Incremental compilation
`zig build -fincremental --watch` rebuilds on every save — but only the **self-hosted**
backend compiles incrementally. Measured on a 10-line program in Debug (Zig 0.17.0, x86_64 Linux, 8-core machine):
self-hosted 479 ms for the first build, then 14 ms and 6 ms per edit; with `.use_llvm = true`
every edit was a full 2–3 s rebuild.
For the edit loop (and while ZLS does not work) run it with the self-hosted backend, e.g.
`zig build -fincremental --watch -Dselfhosted=true` when the build exposes such an option;
test with LLVM. There is no incremental mode without `--watch`.

## Critical: Removed Features (0.15.x)

### `usingnamespace` - REMOVED
```zig
// WRONG - compile error
pub usingnamespace @import("other.zig");

// CORRECT - explicit re-export
const other = @import("other.zig");
pub const foo = other.foo;
```

### `async`/`await` - REMOVED
Keywords removed from the language. Concurrency goes through the `std.Io` interface instead
(`io.async`, `io.concurrent`, `Io.Group`, `Io.Select`).

### `std.BoundedArray` - REMOVED
Use `std.ArrayList` with `initBuffer`:
```zig
var buffer: [8]i32 = undefined;
var stack = std.ArrayList(i32).initBuffer(&buffer);
```

### `std.RingBuffer`, `std.fifo.LinearFifo` - REMOVED
Use `std.Io.Reader`/`std.Io.Writer` ring buffers instead.

### `std.io.SeekableStream`, `std.io.BitReader`, `std.io.BitWriter` - REMOVED

### `std.fmt.Formatter` - REMOVED
Replaced by `std.fmt.Alt`.

### Undefined Behavior Restrictions (0.15.x)
Arithmetic on `undefined` is now **illegal**. Only operators that can never trigger Illegal Behavior permit `undefined` as operand.
```zig
// WRONG - illegal behavior: arithmetic on an undefined value (a compile error when the
// operand is comptime-known, a runtime safety panic or garbage otherwise)
var n: usize = undefined;
while (condition) : (n += 1) {}

// CORRECT - explicit initialization required
var n: usize = 0;
while (condition) : (n += 1) {}

// OK - space reservation (no arithmetic)
var buffer: [256]u8 = undefined;
```

## Critical: Networking Removed — `std.net` → `std.Io.net` (0.16)

`std.net` is **completely removed** in 0.16. Replaced by `std.Io.net`, which requires an `Io` instance.

### Accept Loop
```zig
// WRONG (0.15) — std.net removed
const addr = std.net.Address.parseIp4(host, port) catch unreachable;
var server = addr.listen(.{ .reuse_address = true }) catch unreachable;
const conn = server.accept() catch continue;
defer conn.stream.close();

// CORRECT (0.16) — std.Io.net with Io instance
const addr = try std.Io.net.IpAddress.parse(host, port);
var server = try addr.listen(io, .{ .reuse_address = true });
const stream = try server.accept(io); // returns Stream directly, no .stream wrapper
defer stream.close(io);               // close() now takes io
```

### Io Runtime Setup
```zig
// In an executable, take the Io (and gpa) from main:
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    _ = io;
}
// Elsewhere (a library test harness, a C entry point) create one and thread it through:
// init takes (gpa, options). Without `.environ = init.minimal.environ` in the options,
// child processes started through this Io get an EMPTY environment; in main use init.io.
var threaded: std.Io.Threaded = .init(gpa, .{});
defer threaded.deinit();
const io = threaded.io();
```

### Reading and Writing a Stream
```zig
// Buffered reader/writer over the stream, like files; flush the writer.
var rbuf: [1024]u8 = undefined;
var wbuf: [1024]u8 = undefined;
var reader = stream.reader(io, &rbuf);
var writer = stream.writer(io, &wbuf);
const line = try reader.interface.takeDelimiterExclusive('\n');
try writer.interface.print("echo:{s}\n", .{line});
try writer.interface.flush();

// The raw handle moved: stream.handle → stream.socket.handle
```

### Removed Convenience Functions
```zig
// Connecting: parse an address and connect through Io
const target = try std.Io.net.IpAddress.parse("127.0.0.1", port);
const conn = try target.connect(io, .{ .mode = .stream });
defer conn.close(io);

// std.net.has_unix_sockets → std.Io.net.has_unix_sockets; Unix sockets: std.Io.net.UnixAddress
// std.posix.close/write/connect/socket are gone. Without an Io and already linking libc
// (`.link_libc = true`), std.c.close/write/socket/connect are the fallback.
```

See **[std.net reference](references/std-net.md)** for the std.net → std.Io.net migration and stream I/O.

## Critical: Time APIs Removed (0.16)

`std.time.timestamp()`, `milliTimestamp()`, `microTimestamp()`, `nanoTimestamp()`,
`std.time.Instant` and `std.time.Timer` are **removed**. Clocks are read through the `Io`:

```zig
// WRONG (0.16) — removed
const secs = std.time.timestamp();
const ms = std.time.milliTimestamp();

// CORRECT — std.Io.Clock
const secs = std.Io.Clock.real.now(io).toSeconds();       // wall clock
const ms = std.Io.Clock.real.now(io).toMilliseconds();
const t0 = std.Io.Clock.awake.now(io);                     // monotonic, for timing
const elapsed = t0.durationTo(std.Io.Clock.awake.now(io)); // Io.Duration
```

`std.time.ns_per_s` and the other unit constants are **still present**. Without an `Io` and
already linking libc, `std.c.clock_gettime(.REALTIME, &ts)` is the fallback (`ts.nsec` is
signed: `@divTrunc`, not `/`). See [std.time reference](references/std-time.md).

## Critical: Thread Primitives Removed (0.16)

`std.Thread.Mutex`, `std.Thread.Mutex.Recursive`, `std.Thread.Condition`, `std.Thread.RwLock`, `std.Thread.Semaphore`, `std.Thread.Futex`, `std.Thread.Pool`, `std.Thread.WaitGroup`, `std.Thread.ResetEvent`, and `std.Thread.sleep` are **all removed**.

**First choice — you have an `Io` instance:** use `std.Io.Mutex` / `std.Io.Condition` / `std.Io.RwLock` / `std.Io.Semaphore` (each method takes `io: Io`), `io.futexWait`/`io.futexWake` for raw futex ops, and `io.sleep(duration, clock)` instead of `Thread.sleep`.

```zig
// WRONG (0.16)
var mutex: std.Thread.Mutex = .{};
mutex.lock();

// CORRECT — std.Io.Mutex, needs an `io: Io`
var mutex: std.Io.Mutex = .init;
try mutex.lock(io);
defer mutex.unlock(io);
```

**Library code with no `Io` available, on Linux:** build a tiny lock on the raw futex syscall (`std.os.linux.futex`), not libc:

```zig
const FutexLock = struct {
    state: std.atomic.Value(u32) = .init(0), // 0 = unlocked, 1 = locked

    pub fn lock(l: *FutexLock) void {
        while (l.state.swap(1, .acquire) != 0) {
            _ = std.os.linux.futex_4arg(&l.state.raw, .{ .cmd = .WAIT, .private = true }, 1, null);
        }
    }

    pub fn unlock(l: *FutexLock) void {
        l.state.store(0, .release);
        _ = std.os.linux.futex_3arg(&l.state.raw, .{ .cmd = .WAKE, .private = true }, 1);
    }
};
```

**Last resort — code that already links libc, needs to run on non-Linux too:** the POSIX pthread shim:

```zig
const PthreadMutex = struct {
    inner: std.c.pthread_mutex_t = std.c.PTHREAD_MUTEX_INITIALIZER,
    pub fn lock(m: *@This()) void { _ = std.c.pthread_mutex_lock(&m.inner); }
    pub fn unlock(m: *@This()) void { _ = std.c.pthread_mutex_unlock(&m.inner); }
    pub fn tryLock(m: *@This()) bool {
        return @backingInt(std.c.pthread_mutex_trylock(&m.inner)) == 0;
    }
};

// std.Thread.sleep → nanosleep (no Io, already linking libc)
fn threadSleep(ns: u64) void {
    const ts = std.c.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.c.nanosleep(&ts, null);
}
```

`std.Thread.spawn` — **unchanged**.

See **[std.Thread reference](references/std-thread.md)** for complete threading documentation including PthreadCondition.

## Critical: Debug Stderr Changed (0.16)

```zig
// WRONG (0.16) — lockStderrWriter removed
const stderr = std.debug.lockStderrWriter();
defer std.debug.unlockStderr();
try stderr.print("msg\n", .{});

// CORRECT — lockStderr with buffer
var buf: [4096]u8 = undefined;
const held = std.debug.lockStderr(&buf);
defer std.debug.unlockStderr();
try held.file_writer.interface.print("msg\n", .{});
try held.file_writer.interface.flush();
```

## Critical: `std.crypto.random` Removed (0.16)

```zig
// WRONG (0.16) — removed
std.crypto.random.bytes(&nonce);

// CORRECT — through the Io (portable)
try io.randomSecure(&nonce);
```

For the full `std.Random` interface seed `std.Random.DefaultCsprng` from `io.randomSecure`
once. Library code with no `Io` on Linux can call the syscall, but must check it — a failed
or short call leaves the key bytes undefined:

```zig
fn getrandomChecked(buf: []u8) !void {
    const linux = std.os.linux;
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = linux.getrandom(buf[filled..].ptr, buf.len - filled, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => filled += rc,
            .INTR => continue,
            else => return error.GetRandomFailed,
        }
    }
}
```

`std.posix.getrandom` does not exist. See [std.crypto reference](references/std-crypto.md).

## Critical: Scoping Rule Tightened (0.16)

Local constants **cannot shadow** module-level `extern` declarations:
```zig
extern "c" fn socket(...) c_int;

fn myConnect() !void {
    // WRONG — "local constant shadows declaration of socket"
    const socket = blk: { ... };

    // CORRECT — use different name
    const sock_fd = blk: { ... };
}
```

## Critical: I/O API Rewrite ("Writergate")

The entire `std.io` API changed. New `std.Io.Writer` and `std.Io.Reader` are **non-generic** with buffer in the interface.

### Writing
```zig
// WRONG - old API
const stdout = std.io.getStdOut().writer();
try stdout.print("Hello\n", .{});

// CORRECT - new API: provide buffer, access .interface, flush
// `io` comes from an `Io` implementation (e.g. create `var threaded: std.Io.Threaded = .init(gpa, .{})` and `threaded.io()` as in the Io section above; in an executable use `init.io`, a bare `.init(gpa, .{})` starts children with an empty environment)
var buf: [4096]u8 = undefined;
var stdout_writer = std.Io.File.stdout().writer(io, &buf);
const stdout = &stdout_writer.interface;
try stdout.print("Hello\n", .{});
try stdout.flush();  // REQUIRED!
```

**Note (0.16):** `std.fs.File` is gone — file handles are `std.Io.File` now, and `.reader()`/`.writer()` take an `io: Io` argument (`file.writer(io, &buf)`), because the actual read/write syscalls go through the `Io` implementation.

### Reading
```zig
// Reading from file
var buf: [4096]u8 = undefined;
var file_reader = file.reader(io, &buf);
const r = &file_reader.interface;

// Read line by line (takeDelimiter returns null at EOF)
while (try r.takeDelimiter('\n')) |line| {
    // process line (doesn't include '\n')
}

// Read binary data
const header = try r.takeStruct(Header, .little);
const value = try r.takeInt(u32, .big);
```

### Fixed Buffer Writer (no file)
```zig
var buf: [256]u8 = undefined;
var w: std.Io.Writer = .fixed(&buf);
try w.print("Hello {s}", .{"world"});
const result = w.buffered();  // "Hello world"
```

### Fixed Reader (from slice)
```zig
var r: std.Io.Reader = .fixed("hello\nworld");
const line = (try r.takeDelimiter('\n')).?;  // "hello" (returns null at EOF)
```

**Removed:** `BufferedWriter`, `CountingWriter`, `std.io.bufferedWriter()`

**Deprecated:** `GenericWriter`, `GenericReader`, `AnyWriter`, `AnyReader`, `FixedBufferStream`

**New:** `std.Io.Writer`, `std.Io.Reader` - non-generic, buffer in interface

**Replacements:**
- `CountingWriter` -> `std.Io.Writer.Discarding` (has `.fullCount()`)
- `BufferedWriter` -> buffer provided to `.writer(&buf)` call
- Allocating output -> `std.Io.Writer.Allocating`

### `std.io.fixedBufferStream` Removed (0.16)
```zig
// WRONG (0.16) — std.io (lowercase) removed entirely
var buf: [512]u8 = undefined;
var stream = std.io.fixedBufferStream(&buf);
try std.fmt.format(stream.writer(), "{d}", .{value});
const result = stream.getWritten();

// CORRECT — format straight into the buffer (0.17: std.mem.print; std.fmt.bufPrint is deprecated)
var buf: [512]u8 = undefined;
const result = try std.mem.print(&buf, "{d}", .{value});
```

### Vtable Writer Type Changed (0.16)
```zig
// WRONG — *std.io.Writer (lowercase)
fn drain(w: *std.io.Writer) error{WriteFailed}!usize { ... }

// CORRECT — *std.Io.Writer (capital)
fn drain(w: *std.Io.Writer) error{WriteFailed}!usize { ... }
```

## Critical: Build System (0.15.x)

`root_source_file` is REMOVED from `addExecutable`/`addLibrary`/`addTest`. Use `root_module`:

```zig
// WRONG - removed field
b.addExecutable(.{
    .name = "app",
    .root_source_file = b.path("src/main.zig"),  // ERROR
    .target = target,
});

// CORRECT
b.addExecutable(.{
    .name = "app",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    }),
});
```

**Module imports changed:**
```zig
// WRONG (old API)
exe.addModule("helper", helper_mod);

// CORRECT
exe.root_module.addImport("helper", helper_mod);
```

**Libraries: `addSharedLibrary` → `addLibrary` with `.linkage`:**
```zig
// WRONG - removed function
const lib = b.addSharedLibrary(.{ .name = "mylib", ... });

// CORRECT - unified addLibrary with linkage field
const lib = b.addLibrary(.{
    .name = "mylib",
    .linkage = .dynamic,  // or .static (default)
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    }),
});
```

**Adding dependency modules:**
```zig
const dep = b.dependency("lib", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("lib", dep.module("lib"));
```

### `Compile.*` Methods Moved to `Module.*` (0.16)

In 0.16, methods like `addIncludePath`, `addLibraryPath`, `linkSystemLibrary`, `addCSourceFile` moved from the `Compile` step to the module:
```zig
// WRONG (0.16) — methods no longer on Compile
lib.addIncludePath(.{ .cwd_relative = path });
lib.linkSystemLibrary("foo");
lib.addCSourceFile(.{ .file = b.path("shim.c"), .flags = &.{} });

// CORRECT — use root_module
lib.root_module.addIncludePath(b.graph.cwdRelativePath(path)); // 0.17: .cwd_relative is deprecated
lib.root_module.linkSystemLibrary("foo", .{});  // note: now takes options struct
lib.root_module.addCSourceFile(.{ .file = b.path("shim.c"), .flags = &.{} });
```

**Common misleading error:** `no field or member function named 'addIncludePath' in 'Build.Step.Compile'`. The note about `.*` is wrong — the fix is `lib.root_module.addIncludePath(...)`.

See **[std.Build reference](references/std-build.md)** for complete build system documentation.

## Critical: Container Initialization

**Never use `.{}` for containers.** Use `.empty` or `.init`:

```zig
// WRONG - deprecated
var list: std.ArrayList(u32) = .{};

// CORRECT - use .empty for empty collections
var list: std.ArrayList(u32) = .empty;
var map: std.AutoHashMapUnmanaged(u32, u32) = .empty;

// CORRECT - use .init for stateful types
var safe: std.heap.SafeAllocator = .init(std.heap.page_allocator, .{}); // 0.17; was DebugAllocator
var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
```

### ArrayList: Unmanaged by Default
`std.ArrayList` is **unmanaged** — no allocator field, pass the allocator to every method that
allocates or frees. The managed variant `std.array_list.Managed` is deprecated in 0.17.
```zig
var list: std.ArrayList(u32) = .empty;
defer list.deinit(allocator);
try list.append(allocator, 42);
```

### HashMap: Managed vs Unmanaged
Same pattern applies — unmanaged variants require allocator per operation:
```zig
// Unmanaged (no internal allocator)
var map: std.StringHashMapUnmanaged(u32) = .empty;
try map.put(allocator, "key", 42);
map.deinit(allocator);

// Managed (stores allocator internally)
var map = std.StringHashMap(u32).init(allocator);
try map.put("key", 42);
map.deinit();
```

### ArrayList Empty Init
Neither `.{}` nor a hand-written field literal initializes an `ArrayList`: 0.17 added a
`pointer_stability` field without a default.
```zig
// WRONG — .{} (no defaults) and a field literal (0.17: missing pointer_stability)
._list = .{},
._list = .{ .items = &.{}, .capacity = 0 },

// CORRECT
._list = .empty,
```

### Naming Changes
- **`std.ArrayListUnmanaged` -> `std.ArrayList`** (Unmanaged is now default, old name deprecated)
- **`std.heap.GeneralPurposeAllocator` / `DebugAllocator` -> `std.heap.SafeAllocator`** (0.17;
  `DebugAllocator` is deprecated). In `main(init: std.process.Init)` use `init.gpa`: a `SafeAllocator` in Debug/ReleaseSafe
  (and in ReleaseFast/Small when single-threaded without libc); otherwise `c_allocator` when
  linking libc, `wasm_allocator` on wasm, `smp_allocator` elsewhere (`std/start.zig`).
  `init.io` is an `Io.Threaded` that `start.zig` builds on that same `gpa`
  (`.init(gpa, .{ .argv0 = .init(.{ .vector = args }), .environ = .{ .block = environ } })`), so a program
  that replaces `init.gpa` (to leave `smp_allocator`) keeps every allocation inside `Io` on the
  old one. Replace both: build your own `std.Io.Threaded` on the new allocator, pass
  `.argv0 = .init(.{ .vector = init.minimal.args.vector })` and
  `.environ = init.minimal.environ`; without `.environ` the `Io` starts children with an empty
  environment. A soak run in one project: `smp_allocator` +5.4 MB/min, only `init.gpa` swapped
  +0.7 MB/min, `init.gpa` and `init.io` swapped flat (not re-run for this skill; the
  `start.zig` lines are read from the source).
- **`SafeAllocator` over `std.heap.page_allocator` can serve as the GPA of a long-running
  daemon, not only for tests; measure RSS on your own workload first.** Its header says "Given
  the backing allocator does not reuse memory, this does not reuse memory either"; that is a
  statement about the *backing*: `free` hands memory back to the backing (`SafeAllocator.zig`
  `free`, `rawFree` calls), and `page_allocator` returns pages to the OS. Measured in a
  migration (host build, ReleaseSafe, 200 000 MQTT connect/publish/leave cycles): RSS flat at
  28.2-28.3 MB for `SafeAllocator` and for the old `DebugAllocator`, while an `ArenaAllocator`
  negative control grew 9.3 kB per cycle; not re-run for this skill. **Caveat:** small
  allocations live in linearly filled 8 KiB buckets (`SafeAllocator.zig` `bucket_size_log2`)
  and a bucket goes back to the backing only when every allocation in it is freed; slots inside
  a bucket are not reused. One long-lived small object pins its whole bucket, so a daemon that
  mixes long-lived small objects with per-request garbage can grow where the MQTT churn stayed
  flat (probe on 0.17.0, 200 000 x 64 B with 1 in 64 kept alive, 195 KiB live: RSS 748 ->
  14988 KiB in ReleaseSafe, 4596 -> 29716 KiB in Debug).

### Linked Lists: Generic Parameter Removed
```zig
// WRONG - old API
const Node = std.DoublyLinkedList(MyData).Node;

// CORRECT - non-generic, use @fieldParentPtr
const MyNode = struct {
    node: std.DoublyLinkedList.Node,
    data: MyData,
};
// Access: const my_node = @fieldParentPtr("node", node_ptr);
```

### Process API: Term is Tagged Union
```zig
// WRONG - direct field access removed
if (result.term.Exited != 0) {}

// CORRECT - pattern match
switch (result.term) {
    .exited => |code| if (code != 0) { /* handle */ },
    else => {},
}
```

## Critical: Format Strings (0.15.x)

`{f}` required to call format methods:
```zig
// WRONG - ambiguous error
std.debug.print("{}", .{std.zig.fmtId("x")});

// CORRECT
std.debug.print("{f}", .{std.zig.fmtId("x")});
```

Format method signature changed:
```zig
// OLD - wrong
pub fn format(self: @This(), comptime fmt: []const u8, opts: std.fmt.FormatOptions, writer: anytype) !void

// NEW - correct
pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void
```

## Breaking Changes (0.14.0+)

### `@branchHint` replaces `@setCold`
```zig
// WRONG
@setCold(true);

// CORRECT
@branchHint(.cold);  // Must be first statement in block
```

### `@export` takes pointer
```zig
// WRONG
@export(foo, .{ .name = "bar" });

// CORRECT
@export(&foo, .{ .name = "bar" });
```

### Inline asm clobbers are typed
```zig
// WRONG
: "rcx", "r11"

// CORRECT
: .{ .rcx = true, .r11 = true }
```

### `@fence` - REMOVED
Use stronger atomic orderings or RMW operations instead.

### `@typeInfo` fields now lowercase
```zig
// WRONG - old PascalCase (compile error)
if (@typeInfo(T) == .Struct) { ... }
if (@typeInfo(T) == .Slice) { ... }
if (@typeInfo(T) == .Int) { ... }

// CORRECT - lowercase, keywords escaped with @""
if (@typeInfo(T) == .@"struct") { ... }
if (@typeInfo(T) == .@"enum") { ... }
if (@typeInfo(T) == .@"union") { ... }
if (@typeInfo(T) == .@"opaque") { ... }
if (@typeInfo(T) == .slice) { ... }
if (@typeInfo(T) == .int) { ... }
if (@typeInfo(T) == .bool) { ... }
if (@typeInfo(T) == .pointer) { ... }

// Accessing fields (0.17: struct-of-arrays, see "Zig 0.17.0 Changes"):
const names = @typeInfo(T).@"struct".field_names;
const types = @typeInfo(T).@"struct".field_types;
const tag_type = @typeInfo(T).@"enum".tag_type;
```

## Decl Literals (0.14.0+)

`.identifier` syntax works for declarations:
```zig
const S = struct {
    x: u32,
    const default: S = .{ .x = 0 };
    fn init(v: u32) S { return .{ .x = v }; }
};

const a: S = .default;      // S.default
const b: S = .init(42);     // S.init(42)
const c: S = try .init(1);  // works with try
```

## Labeled Switch (0.14.0+)

State machines use `continue :label`:
```zig
state: switch (initial) {
    .idle => continue :state .running,
    .running => if (done) break :state result else continue :state .running,
    .failed => return error.Failed,
}
```

## Non-exhaustive Enum Switch (0.15.x)

Can mix explicit tags with `_` and `else`:
```zig
switch (value) {
    .a, .b => {},
    else => {},  // other named tags
    _ => {},     // unnamed integer values
}
```

## Critical: HTTP API Reworked (0.15.x)

HTTP client/server completely restructured — depends only on I/O streams, not networking:
```zig
// Server now takes Reader/Writer interfaces, not connection directly
var recv_buffer: [4000]u8 = undefined;
var send_buffer: [4000]u8 = undefined;
var conn_reader = stream.reader(io, &recv_buffer); // stream = try server.accept(io)
var conn_writer = stream.writer(io, &send_buffer);
var server = std.http.Server.init(
    &conn_reader.interface,
    &conn_writer.interface,
);
```
**Note:** the HTTP client API still changes between Zig releases. For stability-critical code, pin the Zig version (`minimum_zig_version` in `build.zig.zon`) and wrap the client behind your own small interface.

## Quick Fixes

| Error | Fix |
|-------|-----|
| `no field 'root_source_file'` | Use `root_module = b.createModule(.{...})` |
| `'std.net' has no member 'Stream'` | Networking moved: use `std.Io.net.Stream` (0.16) |
| `'std.net' has no member 'Address'` | Use `std.Io.net.IpAddress.parse(host, port)` (0.16) |
| `no field 'addIncludePath' in 'Compile'` | Methods moved: `lib.root_module.addIncludePath(...)` (0.16) |
| `'timestamp' not found in 'std.time'` | Removed (0.16): `std.Io.Clock.real.now(io)` (wall) / `.awake` (monotonic) |
| `'Mutex' not found in 'std.Thread'` | Removed: use `std.Io.Mutex` (needs `Io`); no `Io`: raw futex on Linux, POSIX `PthreadMutex` shim as last resort (0.16) |
| `'random' not found in 'std.crypto'` | Removed (0.16): `io.randomSecure(&buf)`; without an `Io`, `std.os.linux.getrandom` |
| `'lockStderrWriter' not found` | Renamed: use `std.debug.lockStderr(&buf)` (0.16) |
| `local constant shadows declaration` | 0.16 forbids local names matching module-level `extern fn` — rename local |
| `signed integer division` | Use `@divTrunc(a, b)` (or `@divFloor`) not `a / b` for signed integers |
| `no field 'close' in 'posix'` | `std.posix.close` removed (0.16): close through the owning `Io` type (`file.close(io)`, `stream.close(io)`); a raw fd with libc linked: `_ = std.c.close(fd)` |
| `use of undefined value` | Arithmetic on `undefined` is now illegal — initialize explicitly |
| `type 'f32' cannot represent integer` | Use float literal: `123_456_789.0` not `123_456_789` |
| `ambiguous reference` (note: `also declared here`) | a declaration inside a struct has the same name as a file-level or outer declaration the struct body also refers to; rename one (seen on 0.17.0 after a migration added a decl whose name an outer one already had) |
| `ambiguous format string` | Use `{f}` for format methods |
| `no field 'append'` on ArrayList | Pass allocator: `list.append(allocator, val)` (unmanaged default) |
| `expected 2 arguments, found 1` on ArrayList | Add allocator param: `.append(allocator, val)`, `.deinit(allocator)` |
| `BoundedArray` not found | Use `std.ArrayList(T).initBuffer(&buf)` |
| `GenericWriter`/`GenericReader` | Use `std.Io.Writer`/`std.Io.Reader` |
| missing `.flush()` — no output | Always call `try writer.flush()` after writing |
| `enum has no member named 'Struct'` | `@typeInfo` fields now lowercase: `.@"struct"`, `.slice`, `.int` |
| `no field named 'encode'` on base64 | Use `std.base64.standard.Encoder.encode()` |
| `no field named 'open'` on HTTP | Use `client.request()` or `client.fetch()` |
| `expected error union, found Signature` | `Ed25519.Signature.fromBytes()` doesn't return error — remove `try` |
| `addSharedLibrary` not found | Use `b.addLibrary(.{ .linkage = .dynamic, ... })` |
| `binary operator '*' has whitespace on one side` at `} ** n` | Array `**` removed (0.17): `const a: [n]T = @splat(x);` |
| `expected block or expression, found '\|'` after `errdefer` | errdefer capture removed (0.17): catch in a wrapper function |
| `invalid builtin function: '@cImport'` | Removed (0.17): `translate-c` package, `Translator.init` in build.zig |
| `no field named 'fields' in struct 'lang.Type.Struct'` | SoA type info (0.17): `field_names`, `field_types`, `field_attrs` |
| `cannot @bitCast from '<extern struct>'` | 0.17: `@ptrCast` to `*align(1) const T`, or an extern union |
| `cannot @bitCast to '<extern struct>'` (bytes into a C struct, e.g. `os.linux.sockaddr.in`) | 0.17: `std.mem.bytesToValue(T, bytes[0..@sizeOf(T)])` (copy) or `std.mem.bytesAsValue` (pointer) |
| `struct 'fmt' has no member named 'bufPrintZ'` | 0.17: `std.mem.printSentinel(buf, fmt, args, 0)` |
| `no field or member function named 'dupeZ' in 'mem.Allocator'` | 0.17: `allocator.dupeSentinel(u8, s, 0)` |
| `struct 'meta' has no member named 'Int'` | 0.17: builtin `@Int(.unsigned, n)` |
| `deprecated in favor of @typeInfo` at `std.meta.fields` | 0.17: `@typeInfo(T).@"struct".field_names` / `field_types` |
| `error: configuration failed: FileSystemFailure` | 0.17: `dependOn…Contents` on a path that does not exist — declare the nearest existing ancestor |
| `no field named 'args' in struct 'Build'` | 0.17: `run_cmd.addPassthruArgs()` |
| `no field named 'build_root' in struct 'Build'` | 0.17: `b.root` (a `Cache.Path`) |
| `no field named 'ReleaseFast' in enum 'lang.Optimize'` | 0.17: `.debug`, `.safe`, `.fast`, `.small` |
| `'zon.parse' has no member named 'fromSliceAlloc'` | 0.17: `std.zon.parse.fromSlice(T, .{ .gpa, .arena, .source, .diagnostics })` |
| `missing struct field: pointer_stability` | 0.17 ArrayList: initialize with `.empty`, not a field literal |
| `expected error union type, found '...X25519.KeyPair'` | 0.17: it no longer fails — drop the `try` (`X25519.recoverPublicKey` likewise returns a plain `[32]u8`: `crypto/25519/x25519.zig:35,65`). Generic code over several DH types that still `try`s a call that may now be infallible: `try @as(anyerror!KeyPair, KP.generateDeterministic(seed))` |

## Verification Workflow

After writing or modifying Zig code, verify with this sequence:
1. `zig build` — catch compilation errors, match against Quick Fixes above
2. `zig build test` — run unit tests (Debug: self-hosted backend on x86_64 Linux unless the
   build sets `.use_llvm = true`, see below)
3. Before a release: `zig build test -Doptimize=ReleaseSafe` and `-Doptimize=ReleaseFast` —
   ReleaseSafe keeps the safety checks with the optimizer on; ReleaseFast turns them off and
   shows bugs that exist only in optimized code (inlining, inline-asm constraints, reads of
   `undefined`)

**Development speed tips:**
- `zig build --watch -fincremental` — incremental compilation, rebuilds on file change (0.17:
  works for most x86_64-linux projects)
- Debug on x86_64 Linux uses the self-hosted backend: 2–6x faster to compile than LLVM, but
  its code runs 2–3x slower (measured on 0.16.0, see gotchas). Use it for the edit loop and LLVM (`-fllvm`, `.use_llvm = true`)
  for test runs — see [gotchas](references/zig-gotchas.md), "Two backends"

## Common Pitfalls

- **Forgetting `defer`/`errdefer` cleanup** — place cleanup immediately after resource acquisition
- **Using `anyerror` instead of specific error sets** — explicit sets document failure modes
- **Ignoring error unions** — handle or propagate, never discard
- **Missing `errdefer` after allocations in multi-step init** — partial construction leaks
- **Expecting comptime side effects** — comptime code is evaluated lazily
- **Unhandled integer overflow** — Zig traps on overflow in debug builds
- **Missing null terminators for C strings** — use `:0` sentinel slices: `[:0]const u8`
- **Using `anytype` when `comptime T: type` works** — explicit types produce clearer errors
- **Scoped loggers**: always define per-module `const log = std.log.scoped(.my_module);` for filterable logging

## Learning Resources

Production Zig codebases worth studying:
- **[Bun](https://github.com/oven-sh/bun)** — JS runtime (~200k+ lines), async I/O, FFI, system calls
- **[Ghostty](https://github.com/ghostty-org/ghostty)** — Terminal emulator, cross-platform, GPU rendering
- **[TigerBeetle](https://github.com/tigerbeetle/tigerbeetle)** — Financial DB, deterministic execution, VOPR fuzzing
- **[Mach Engine](https://github.com/hexops/mach)** — Game engine, graphics, ECS
- **[Sig](https://github.com/Syndica/sig)** — Solana validator, high-performance networking

## Language References

Load these references when working with core language features:

### Code Style
- **[Style Guide](references/style-guide.md)** - Official Zig naming conventions (TitleCase types, camelCase functions, snake_case variables), whitespace rules, doc comment guidance, redundancy avoidance, `zig fmt`

### Language Basics & Built-ins
- **[Language Basics](references/language.md)** - Core language: types, control flow (if/while/for/switch), error handling (try/catch/errdefer), optionals, structs, enums, unions, pointers, slices, comptime, functions
- **[Built-in Functions](references/builtins.md)** - All `@` built-ins: type casts (@intCast, @bitCast, @ptrCast), arithmetic (@addWithOverflow, @divExact), bit ops (@clz, @popCount), memory (@memcpy, @sizeOf), atomics (@atomicRmw, @cmpxchgWeak), introspection (@typeInfo, @TypeOf, @hasDecl), SIMD (@Vector, @splat, @reduce), exports (@export; @cImport is removed in 0.17, see the translate-c package)

## Standard Library References

Load these references when working with specific modules:

### Memory & Slices
- **[std.mem](references/std-mem.md)** - Slice search/compare, split/tokenize, alignment, endianness, byte conversion

### Text & Encoding
- **[std.fmt](references/std-fmt.md)** - Format strings, integer/float parsing, hex encoding, custom formatters, `{f}` specifier (0.15.x)
- **[std.ascii](references/std-ascii.md)** - ASCII character classification (isAlpha, isDigit), case conversion, case-insensitive comparison
- **[std.unicode](references/std-unicode.md)** - UTF-8/UTF-16 encoding/decoding, codepoint iteration, validation, WTF-8 for Windows
- **[std.base64](references/std-base64.md)** - Base64 encoding/decoding (standard, URL-safe, with/without padding)

### Math & Random
- **[std.math](references/std-math.md)** - Floating-point ops, trig, overflow-checked arithmetic, constants, complex numbers, big integers
- **[std.Random](references/std-random.md)** - PRNGs (Xoshiro256, Pcg), CSPRNGs (ChaCha), random integers/floats/booleans, shuffle, distributions
- **[std.hash](references/std-hash.md)** - Non-cryptographic hash functions (Wyhash, XxHash, FNV, Murmur, CityHash), checksums (CRC32, Adler32), auto-hashing

### SIMD & Vectorization
- **[std.simd](references/std-simd.md)** - SIMD vector utilities: optimal vector length, iota/repeat/join/interlace patterns, element shifting/rotation, parallel searching, prefix scans, branchless selection

### Time & Timing
- **[std.time](references/std-time.md)** - Io.Clock timestamps and durations (Instant/Timer are gone), epoch conversions, calendar utilities (year/month/day), time unit constants
- **[std.Tz](references/std-tz.md)** - TZif timezone database parsing (RFC 8536), UTC offsets, DST rules, timezone abbreviations, leap seconds

### Sorting & Searching
- **[std.sort](references/std-sort.md)** - Sorting algorithms (pdq, block, heap, insertion), binary search, min/max

### Core Data Structures
- **[std.ArrayList](references/std-arraylist.md)** - Dynamic arrays, vectors, BoundedArray replacement
- **[std.HashMap / AutoHashMap](references/std-hashmap.md)** - Hash maps, string maps, ordered maps
- **[std.ArrayHashMap](references/std-array-hash-map.md)** - Insertion-order preserving hash map, array-style key/value access
- **[std.MultiArrayList](references/std-multi-array-list.md)** - Struct-of-arrays for cache-efficient struct storage
- **[std.SegmentedList](references/std-segmented-list.md)** - Removed in 0.16 (historical technique page): stable pointers, arena-friendly, non-copyable types
- **[std.DoublyLinkedList / SinglyLinkedList](references/std-linked-list.md)** - Intrusive linked lists, O(1) insert/remove
- **[std.PriorityQueue](references/std-priority-queue.md)** - Binary heap, min/max extraction, task scheduling
- **[std.PriorityDequeue](references/std-priority-dequeue.md)** - Min-max heap, double-ended priority extraction
- **[std.Treap](references/std-treap.md)** - Self-balancing BST, ordered keys, min/max/predecessor
- **[std.bit_set](references/std-bit-set.md)** - Bit sets (Static, Dynamic, Integer, Array), set operations, iteration
- **[std.BufMap / BufSet](references/std-buf-map.md)** - String-owning maps and sets, automatic key/value memory management
- **[std.StaticStringMap](references/std-static-string-map.md)** - Compile-time optimized string lookup, perfect hash for keywords
- **[std.enums](references/std-enums.md)** - EnumSet, EnumMap, EnumArray: bit-backed enum collections

### Allocators
- **[std.heap](references/std-allocators.md)** - Allocator selection guide, ArenaAllocator, SafeAllocator, FixedBufferAllocator, MemoryPool, SmpAllocator, BufferFirstAllocator, custom allocator implementation

### I/O & Files
- **[std.io](references/std-io.md)** - Reader/Writer API (introduced 0.15, valid in 0.17): buffered I/O, streaming, binary data, format strings
- **[std.fs](references/std-fs.md)** - File system: files, directories, iteration, atomic writes, paths
- **[std.tar](references/std-tar.md)** - Tar archive reading/writing, extraction, POSIX ustar, GNU/pax extensions
- **[std.zip](references/std-zip.md)** - ZIP archive reading/extraction, ZIP64 support, store/deflate compression
- **[std.compress](references/std-compress.md)** - Compression: DEFLATE (gzip, zlib), Zstandard, LZMA, LZMA2, XZ decompression/compression

### Networking
- **[std.http](references/std-http.md)** - HTTP client/server, TLS (std TLS does not check that an issuer is a CA: pin the certificate), connection pooling, compression, WebSocket
- **[std.net](references/std-net.md)** - std.net → std.Io.net migration: TCP and Unix sockets, address parsing, connecting by host name, stream I/O
- **[std.Uri](references/std-uri.md)** - URI parsing/formatting (RFC 3986), percent-encoding/decoding, relative URI resolution

### Process Management
- **[std.process](references/std-process.md)** - Child process spawning, environment variables, argument parsing, exec

### OS-Specific APIs
- **[std.os](references/std-os.md)** - OS-specific APIs: Linux syscalls, io_uring, Windows NT APIs, WASI, direct platform access
- **[std.c](references/std-c.md)** - C ABI types and libc bindings: platform-specific types (fd_t, pid_t, timespec), errno values, socket/signal/memory types, fcntl/open flags, FFI with C libraries

### Concurrency
- **[std.Thread](references/std-thread.md)** - `Thread.spawn` and utilities; Io.Mutex/Condition/Event/Group replacements for the removed Thread.Mutex/RwLock/Condition/Semaphore/WaitGroup/Pool, pthread/futex fallbacks
- **[std.atomic](references/std-atomic.md)** - Lock-free atomic operations: Value wrapper, fetch-and-modify (add/sub/and/or/xor), compare-and-swap, atomic ordering semantics, spin loop hints, cache line sizing

### Patterns & Best Practices
- **[Hardware SIMD intrinsics](references/simd-intrinsics.md)** - Beyond `@Vector`: calling LLVM target intrinsics (`extern fn @"llvm.x86.avx2.pmadd.wd"` / `@"llvm.aarch64.neon.udot…"`) for ops with no `@Vector` form (udot, vpsadbw, vpmaddubsw); why this beats inline asm (optimizer-transparent vs opaque); perf gotchas (natural result layout, comptime mode params, manual unroll); cross-arch validation via Rosetta / static-musl + scp / asm-diff
- **[Data-Oriented Design](references/data-oriented-design.md)** - **Load when designing data structures for hot paths, large homogeneous collections, compilers/parsers, ECS, or any memory-footprint-bound code.** From Andrew Kelley's DoD talk applied to the Zig compiler: cache-line mental model (CPU fast, memory slow; compute over memoize), struct size/alignment/padding rules, and six shrink-the-struct techniques — indexes instead of pointers (with `enum(u32)` newtype handles), booleans out of band, struct-of-arrays via MultiArrayList, sparse data in hash maps, encodings instead of fat tagged unions, and constraining ranges/dropping derivable data. Includes the compiler case study (token 64→5 B, AST 120→15.6 B, ZIR 54→20.3 B; −22% then −39% wall-clock) and an anti-pattern checklist
- **[Quality Tooling](references/quality-tooling.md)** - Coverage (kcov, and why in-file tests wreck the denominator), dead-code detection (nothing finds unused *functions* — compiler laziness, zlint's `unused-decls` covers only constants), duplicate detection (jscpd + the `--max-lines` trap), zlint (⚠️ Homebrew's `zlint` is an X.509 linter), and the built-in fuzzer (`*Smith` signature, corpus economics, coverage plateaus)
- **[Zig Patterns](references/patterns.md)** - **Load when writing new code or reviewing code quality.** Comprehensive best practices extracted from the Zig standard library: quick patterns (memory/allocators, file I/O, HTTP, JSON, testing, build system) plus idiomatic code patterns covering syntax (closures, context pattern, options structs, destructuring), polymorphism (duck typing, generics, custom formatting, dynamic/static dispatch), safety (diagnostics, error payloads, defer/errdefer, compile-time assertions), and performance (const pointer passing)
- **[Production Patterns](references/production-patterns.md)** - **Load when building large-scale Zig systems or optimizing performance.** Real-world patterns from Bun, Ghostty, TigerBeetle: modular build systems, CPU feature locking, pre-allocated message pools, counting allocators, SIMD with scalar fallback, intrusive linked lists, cache-line aligned SoA, work-stealing thread pools, SmolStr (15-byte SSO), comptime string maps, EnumUnionType generation, VOPR fuzzing, snapshot testing, edge-biased fuzz generation, platform abstraction facades, Objective-C bridges, opaque C wrappers with RAII, packed struct bitfields, Result union types, radix sort, tournament trees
- **[MCP Server Patterns](references/mcp-server-patterns.md)** - **Load when building MCP servers, LSP bridges, JSON-RPC services, or protocol translators in Zig.** Patterns from zig-mcp: newline-delimited vs Content-Length transport, thread-based request correlation with ResetEvent, arena-per-request memory, child process lifecycle with pipe ownership transfer, tool registry with function pointers, std.json.Stringify for manual JSON building, lazy document sync with double-check locking, graceful degradation, auto-reconnect on crash, comptime schema generation, file URI encoding, common serialization gotchas
- **[Gotchas](references/zig-gotchas.md)** - **Load when debugging code that compiles but misbehaves, or before a release.** Traps found in production code, each with its 0.17.0 status: what 0.17 changed silently (@bitCast arrays, @hasDecl, containsAtLeastScalar, SafeAllocator RSS), tuple swap, generic struct identity, @intFromFloat range, cancellation behind Io.Reader, fiber contextSwitch, fuzz corpus length prefix, self-hosted vs LLVM backend, allocRemaining limit, a struct holding a slice into its own field, byte-loop array/vector @bitCast, HashMap tombstones, byte-loop memcmp/secureZero, key schedules on the stack, build.zig.zon facts
- **[Code Review](references/code-review.md)** - **Load when reviewing Zig code.** Systematic checklist organized by confidence level: ALWAYS FLAG (removed features, changed syntax, API changes), FLAG WITH CONTEXT (exception safety bugs, missing flush, allocator issues), SUGGEST (style improvements). Includes migration examples for 0.14/0.15 breaking changes

### Serialization
- **[std.json](references/std-json.md)** - JSON parsing, serialization, dynamic values, streaming, custom parse/stringify
- **[std.zon](references/std-zon.md)** - ZON (Zig Object Notation) parsing and serialization for build.zig.zon, config files, data interchange

### Testing & Debug
- **[std.testing](references/std-testing.md)** - Unit test assertions and utilities
- **[std.debug](references/std-debug.md)** - Panic, assert, stack traces, hex dump, format specifiers
- **[std.log](references/std-log.md)** - Scoped logging with configurable levels and output

### Metaprogramming
- **[Comptime Reference](references/comptime.md)** - Comptime fundamentals, type reflection (`@typeInfo`, `@TypeOf`; types built with `@Int`/`@Struct`/`@Union`), loop variants (`comptime for` vs `inline for`), branch elimination, type generation, comptime limitations
- **[std.meta](references/std-meta.md)** - Type introspection, field iteration, stringToEnum, generic programming

### Compiler Utilities
- **[std.zig](references/std-zig.md)** - AST parsing, tokenization, source analysis, linters, formatters, ZON parsing

### Security & Cryptography
- **[std.crypto](references/std-crypto.md)** - Hashing (SHA2, SHA3, Blake3), AEAD (AES-GCM, ChaCha20-Poly1305), signatures (Ed25519, ECDSA), key exchange (X25519), password hashing (Argon2, scrypt, bcrypt), secure random, timing-safe operations

### Build System
- **[std.Build](references/std-build.md)** - Build system: build.zig, modules, dependencies, build.zig.zon, steps, options, testing, C/C++ integration

### Interoperability
- **[C Interop](references/c-interop.md)** - Exporting C-compatible APIs: `export fn`, C calling convention, building static/dynamic libraries, creating headers, macOS universal binaries, XCFramework for Swift/Xcode, module maps

## Tooling

### ZLS (Zig Language Server)
IDE support via Language Server Protocol. Provides autocomplete, go-to-definition, hover docs, diagnostics.

**Version matching rule:** Use ZLS release matching your Zig release (0.16.x ZLS for 0.16.x Zig). Nightly Zig needs nightly ZLS.

**Zig 0.17.0: ZLS does not work.** The configurer/maker split removed the build-runner hook
ZLS used; ZLS and Zig are moving it to the Build Server Protocol. Until a ZLS release supports
0.17, compile (`zig build`) to see errors instead of relying on editor diagnostics.

**Installation:** the user's decision — point them at https://github.com/zigtools/zls
(releases, or the VS Code "Zig Language" extension, which bundles it); do not install it on
their behalf. Pick the ZLS release that matches the project's Zig release; for 0.17.0 there is
none yet.

**Editor support:** VS Code, Neovim (nvim-lspconfig), Helix, JetBrains, Emacs (lsp-mode), Sublime Text, Kate.

**Key features:**
- Autocomplete with semantic analysis
- Go-to-definition, find references
- Hover documentation
- Diagnostics (compile errors inline)
- Filesystem completions inside `@import("")` strings
- `std` and `builtin` module path completions
- Snippets for common declarations

### zigup (Version Manager)
Manage multiple Zig versions side-by-side. Useful for migrating between versions.

**Source:** https://github.com/marler8997/zigup

**Installation:** the user's decision — point them at the source link above; do not install toolchains or version managers on their behalf.

**Usage:**
```bash
zigup fetch 0.16.0          # download without changing default
zigup fetch 0.17.0          # download without changing default
zigup list                  # show installed versions
zigup 0.17.0                # set as default
zigup run 0.16.0 build      # run specific version without changing default
zigup run 0.17.0 build test # test with specific version
zigup clean 0.16.0          # remove old version
```

**Migration workflow:**
```bash
zigup run 0.17.0 build 2>&1 | head -40  # try build with new version
# fix errors, re-run until clean
zigup 0.17.0                              # promote to default
```

### anyzig (Version Manager)
Universal Zig version manager — run any Zig version from any project. Replaces manual version switching.

**Source:** https://github.com/marler8997/anyzig

**How it works:**
1. Reads `minimum_zig_version` from `build.zig.zon` (searches up directory tree)
2. Auto-downloads needed compiler version into global cache
3. Invokes the correct `zig` transparently

**Installation:** the user's decision — point them at the source link above; do not install toolchains or version managers on their behalf.

**Usage:**
```bash
# Automatic — reads build.zig.zon minimum_zig_version:
cd myproject && zig build

# Manual version override:
zig 0.13.0 build-exe myproject.zig
zig 0.16.0 build

# Mach engine versions supported:
# Reads .mach_zig_version from build.zig.zon
# Format: 2024.10.0-mach

# anyzig-specific commands:
zig any --help
```

**build.zig.zon version field:**
```zig
.{
    .name = .myproject,
    .version = "0.1.0",
    .minimum_zig_version = "0.17.0",
    // ...
}
```
