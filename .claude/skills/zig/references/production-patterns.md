# Production Zig Patterns

Real-world patterns extracted from Bun (JS runtime, 180k+ LoC), Ghostty (terminal emulator, 100k+ LoC), and TigerBeetle (financial database, 80k+ LoC). These complement [patterns.md](patterns.md) with battle-tested techniques from large-scale Zig projects.

## Table of Contents

- [Build System at Scale](#build-system-at-scale)
- [Memory Management](#memory-management)
- [Data Structures](#data-structures)
- [Concurrency](#concurrency)
- [SIMD & Vectorization](#simd--vectorization)
- [Error Handling](#error-handling)
- [Platform Abstraction](#platform-abstraction)
- [C Interop](#c-interop)
- [Comptime Patterns](#comptime-patterns)
- [String Optimization](#string-optimization)
- [Testing](#testing)
- [Performance](#performance)

---

## Build System at Scale

### Modular Build Architecture (Ghostty)

Large projects delegate build logic to specialized modules instead of one monolithic `build.zig`:

```zig
// build.zig — thin orchestrator
const buildpkg = @import("src/build/main.zig");

pub fn build(b: *std.Build) !void {
    const config = try buildpkg.Config.init(b, appVersion);
    const deps = try buildpkg.SharedDeps.init(b, &config);
    const exe = try buildpkg.GhosttyExe.init(b, &config, &deps);
    // ...
}
```

Central `Config` struct stores all build options. Each artifact (exe, lib, test) has isolated build logic in its own file.

### Hermetic Compiler Version Locking (TigerBeetle)

```zig
comptime {
    const expected = std.SemanticVersion{ .major = 0, .minor = 14, .patch = 1 };
    if (expected.major != builtin.zig_version.major or
        expected.minor != builtin.zig_version.minor or
        expected.patch != builtin.zig_version.patch)
    {
        @compileError(std.fmt.comptimePrint(
            "unsupported zig version: expected {}, found {}",
            .{ expected, builtin.zig_version },
        ));
    }
}
```

Prevents silent ABI/API mismatches from wrong compiler versions.

### CPU Feature Locking (TigerBeetle, Bun)

```zig
fn resolve_target(b: *std.Build, target: []const u8) !std.Build.ResolvedTarget {
    const arch_os, const cpu = inline for (
        .{ "aarch64-linux", "x86_64-linux" },
        .{ "baseline+aes+neon", "x86_64_v3+aes" },
    ) |triple, features| {
        if (std.mem.eql(u8, target, triple)) break .{ triple, features };
    } else return error.UnsupportedTarget;

    return b.resolveTargetQuery(try Query.parse(.{
        .arch_os_abi = arch_os,
        .cpu_features = cpu,
    }));
}
```

Locks feature sets per architecture for reproducible performance. `inline for` compiles to flat dispatch.

### Baseline Detection (Bun)

```zig
pub fn isBaseline(opts: *const BuildOptions) bool {
    return opts.arch.isX86() and
        !Target.x86.featureSetHas(opts.target.result.cpu.features, .avx2);
}
```

Detect at build time whether target supports AVX2. Ship separate baseline/optimized binaries.

---

## Memory Management

### Fast Libc Memory Ops with Fallback (Ghostty)

```zig
pub inline fn move(comptime T: type, dest: []T, source: []const T) void {
    if (builtin.link_libc) {
        _ = memmove(dest.ptr, source.ptr, source.len * @sizeOf(T));
    } else {
        @memmove(dest, source);
    }
}

extern "c" fn memmove(*anyopaque, *const anyopaque, usize) *anyopaque;
```

Libc `memmove` can be 10-20% faster than Zig builtin on large buffers. Inline preserves tight loop performance.

### Pre-Allocated Message Pool (TigerBeetle)

```zig
pub const Message = extern struct {
    header: *Header,
    buffer: *align(constants.sector_size) [constants.message_size_max]u8,
    references: u32 = 0,
    link: FreeList.Link,

    pub fn ref(message: *Message) *Message {
        assert(message.references > 0);
        message.references += 1;
        return message;
    }
};
```

All messages pre-allocated at startup. Sector-aligned buffers for Direct I/O. Reference counting enables zero-copy message passing. No hot-path allocations.

### Counting Allocator Wrapper (TigerBeetle)

```zig
pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
    return .{
        .ptr = self,
        .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free },
    };
}

pub fn live_size(self: *CountingAllocator) u64 {
    return self.alloc_size - self.free_size;
}
```

Wraps any allocator for non-intrusive memory tracking. Query `live_size()` for leak detection.

### Debug Leak Detection Scope (Bun)

```zig
const LockedState = struct {
    parent: std.mem.Allocator,
    history: *History,

    fn alloc(self: Self, len: usize, alignment: Alignment, ret_addr: usize) ![*]u8 {
        const result = self.parent.rawAlloc(len, alignment, ret_addr) orelse
            return error.OutOfMemory;
        errdefer self.parent.rawFree(result[0..len], alignment, ret_addr);
        try self.trackAllocation(result[0..len], ret_addr, .none);
        return result;
    }
};
```

Wraps allocator in Debug mode. Tracks allocation sites with stack traces. Catches use-after-free, double-free. Zero overhead in Release.

### Conditional Allocator Selection (Ghostty)

```zig
self.alloc = if (self.gpa) |*value|
    value.allocator()
else if (builtin.link_libc)
    std.heap.c_allocator
else
    unreachable;
```

Debug: GPA for leak detection. Release: libc malloc (faster). Valgrind: libc (instrumentable). Single decision at startup.

### Mimalloc Thread-Local Arena (Bun)

```zig
pub const Borrowed = struct {
    heap: *mimalloc.Heap,

    fn alignedAlloc(self: Borrowed, len: usize, alignment: Alignment) ?[*]u8 {
        const ptr = if (mimalloc.mustUseAlignedAlloc(alignment))
            mimalloc.mi_heap_malloc_aligned(self.heap, len, alignment.toByteUnits())
        else
            mimalloc.mi_heap_malloc(self.heap, len);
        return if (ptr) |p| @ptrCast(p) else null;
    }
};
```

Thread-local heaps eliminate contention. Borrowed/Owned makes ownership clear at the type level. 2-3x faster than system malloc under contention.

---

## Data Structures

### Segmented Pool for Stable Pointers (Ghostty)

**Removed in 0.16:** `std.SegmentedList` no longer exists in std (no direct replacement). The pattern below is kept as reference for the *idea* (grow without invalidating existing pointers); porting it means vendoring or reimplementing a segmented list yourself.

```zig
// OLD (0.15.x) — std.SegmentedList removed in 0.16, shown for the pattern only
pub fn SegmentedPool(comptime T: type, comptime prealloc: usize) type {
    return struct {
        list: std.SegmentedList(T, prealloc) = .{ .len = prealloc },
        available: usize = prealloc,

        pub fn getGrow(self: *Self, alloc: Allocator) !*T {
            if (self.available == 0) try self.grow(alloc);
            return try self.get();
        }

        fn grow(self: *Self, alloc: Allocator) !void {
            try self.list.growCapacity(alloc, self.list.len * 2);
            self.available = self.list.len;
            self.list.len *= 2;
        }
    };
}
```

Grows without reallocation — pointers never invalidated. Use when callers hold pointers to pool elements (e.g. I/O write requests).

### Fixed-Bucket Cache Table with LRU (Ghostty)

```zig
pub fn CacheTable(comptime K: type, comptime V: type, comptime bucket_count: usize, comptime bucket_size: u8) type {
    return struct {
        buckets: [bucket_count][bucket_size]KV = undefined,
        lengths: [bucket_count]u8 = @splat(0),

        pub fn put(self: *Self, key: K, value: V) ?KV {
            const idx: usize = @intCast(self.context.hash(key) % bucket_count);
            if (self.lengths[idx] < bucket_size) {
                self.buckets[idx][self.lengths[idx]] = kv;
                self.lengths[idx] += 1;
                return null;
            }
            // Rotate oldest out, insert at back
            const evicted = fastmem.rotateIn(KV, &self.buckets[idx], kv);
            if (comptime @hasDecl(Context, "evicted"))
                self.context.evicted(evicted.key, evicted.value);
            return evicted;
        }
    };
}
```

No allocations after init. LRU per bucket via rotate. Optional eviction callback via `@hasDecl`.

### Intrusive Linked Lists (Ghostty, TigerBeetle)

```zig
// TigerBeetle: zero-alloc stack via @fieldParentPtr
pub fn StackType(comptime T: type) type {
    return struct {
        any: StackAny,
        pub inline fn push(self: *Stack, node: *T) void { self.any.push(&node.link); }
        pub inline fn pop(self: *Stack) ?*T {
            const link = self.any.pop() orelse return null;
            return @fieldParentPtr("link", link);
        }
    };
}
```

Node lives inside the struct itself. O(1) insert/remove, zero allocator dependency. Foundation of TigerBeetle's I/O queues and Ghostty's surface lists.

### BoundedArray — Fixed Capacity, No Allocator (TigerBeetle)

```zig
pub fn BoundedArrayType(comptime T: type, comptime capacity: usize) type {
    return struct {
        buffer: [capacity]T = undefined,
        count_u32: u32 = 0,

        pub inline fn push(array: *Self, item: T) void {
            assert(!array.full());
            array.buffer[array.count_u32] = item;
            array.count_u32 += 1;
        }
        pub inline fn unused_capacity_slice(array: *Self) []T {
            return array.buffer[array.count_u32..];
        }
    };
}
```

Capacity baked into type. Stack-allocatable. `unused_capacity_slice` for efficient bulk appends.

### Static HashMap — Compile-Time Sized (Bun)

```zig
pub fn StaticHashMap(comptime K: type, comptime V: type, comptime capacity: usize) type {
    const shift = 63 - math.log2_int(u64, capacity) + 1;
    const overflow = capacity / 10 + (63 - @as(u64, shift) + 1) << 1;
    return struct {
        entries: [capacity + overflow]Entry = [_]Entry{.{}} ** (capacity + overflow),
        len: usize = 0,
    };
}
```

Power-of-two sizing with bit masking. Overflow area for probe chains. Zero allocations; lives on stack or in data section. `maxInt(u64)` as empty sentinel.

---

## Concurrency

### Blocking Queue for Message Passing (Ghostty)

**0.16:** `std.Thread.Mutex`/`std.Thread.Condition` are removed — use `std.Io.Mutex`/`std.Io.Condition`, which need an `io: Io` on every call. `Io.Condition` has `wait(io, mutex)` (cancelable) but no built-in `timedWait`; a bounded wait needs a separate cancellation/timeout mechanism at the `Io` level (e.g. racing the wait against `io.sleep`), not shown here for brevity — only the `.forever` case is a direct port:

```zig
pub fn BlockingQueue(comptime T: type, comptime capacity: usize) type {
    return struct {
        data: [capacity]T = undefined,
        write: u32 = 0,
        read: u32 = 0,
        mutex: std.Io.Mutex = .init,
        cond_not_full: std.Io.Condition = .init,

        pub fn push(self: *Self, io: std.Io, value: T, timeout: Timeout) !u32 {
            try self.mutex.lock(io);
            defer self.mutex.unlock(io);
            if (self.full()) {
                switch (timeout) {
                    .instant => return 0,
                    .forever => try self.cond_not_full.wait(io, &self.mutex),
                    // .ns => bounded wait: needs a timeout mechanism on top of `wait`, see note above
                }
            }
            // ... enqueue
        }
    };
}
```

Fixed capacity prevents unbounded memory growth. Timeout variants: instant (try), timed, forever.

### Work-Stealing Thread Pool (Bun)

```zig
const Sync = packed struct(u32) {
    idle: u14 = 0,
    spawned: u14 = 0,
    unused: bool = false,
    notified: bool = false,
    state: enum(u2) { pending, signaled, waking, shutdown } = .pending,
};

sync: std.atomic.Value(u32) = .init(@as(u32, @bitCast(Sync{}))),
```

Entire sync state fits in one `u32` — CAS updates are all-or-nothing. State machine prevents thundering herd (only one "waking thread" at a time). O(1) task dequeue via work stealing.

### Platform-Specific Mutex with Debug Tracking (Bun)

```zig
const Impl = if (builtin.mode == .Debug and !builtin.single_threaded)
    DebugImpl
else
    ReleaseImpl;

pub const ReleaseImpl = if (builtin.os.tag == .windows) WindowsImpl
    else if (builtin.os.tag.isDarwin()) DarwinImpl
    else FutexImpl;

const DebugImpl = struct {
    locking_thread: std.atomic.Value(Thread.Id) = .init(0),
    impl: ReleaseImpl = .{},
    // panics on double-lock from same thread
};
```

Zero overhead in Release. Debug catches deadlocks from double-locking.

---

## SIMD & Vectorization

### Comptime SIMD with Scalar Fallback (Ghostty)

```zig
pub fn decode(input: []const u8, output: []u8) error{Invalid}![]const u8 {
    if (comptime options.simd)
        return simd_decode(input, output);
    return scalar_decode(input, output);
}

// C-implemented SIMD backend
extern "c" fn ghostty_simd_base64_decode([*]const u8, usize, [*]u8) isize;
```

Build option `simd` (false for wasm, true for native). Single entry point; C side provides SSE4/AVX2 optimizations. Always include scalar fallback for testing and unsupported targets.

### @Vector for Parallel Aggregation (Bun)

```zig
const Vector = @Vector(char_freq_count, i32);

pub fn include(this: *CharFreq, other: CharFreq) void {
    const left: Vector = this.freqs;
    const right: Vector = other.freqs;
    this.freqs = left + right;  // compiles to SIMD add
}

pub fn scan(this: *CharFreq, text: string, delta: i32) void {
    if (text.len < scan_big_chunk_size) scanSmall(&this.freqs, text, delta)
    else scanBig(&this.freqs, text, delta);  // manual unroll, 32 bytes/iter
}
```

`@Vector` addition compiles to hardware SIMD when available. Dispatch on input size to avoid SIMD overhead on small inputs.

### Cache-Line Aligned Tournament Tree (TigerBeetle)

```zig
pub fn TournamentTreeType(comptime Key: type, comptime contestants_max: comptime_int) type {
    return struct {
        loser_keys: [node_count_max]Key align(64),   // SoA, cache-line aligned
        loser_ids: [node_count_max]u32 align(64),     // separate array
        win_key: Key,
        win_id: u32,
    };
}
```

SoA layout prevents false sharing. Each array independently aligned for streaming access. Tournament merge with minimal branches.

### Histogram-Based Radix Sort (TigerBeetle)

```zig
// Build all histograms in one pass
var histograms: Histograms align(64) = @splat(@splat(0));
for (values) |*value| {
    const key = key_from_value(value);
    inline for (0..radix_passes) |pass| {
        const partition_id = (key >> (pass * radix_bits)) & radix_mask;
        histograms[pass][partition_id] += 1;
    }
}
// Skip trivial passes (all items in one bucket)
inline for (0..radix_passes) |pass| {
    const trivial = for (histograms[pass]) |c| { if (c == count) break true; } else false;
    if (!trivial) { /* partition */ }
}
```

Single histogram pass amortizes cache misses. Skips passes where all items land in one bucket.

---

## Error Handling

### Explicit Error Sets per Method (Ghostty)

```zig
pub const Pty = switch (builtin.os.tag) {
    .windows => WindowsPty,
    .ios => NullPty,
    else => PosixPty,
};

const PosixPty = struct {
    pub const OpenError = error{OpenptyFailed};
    pub const GetModeError = error{GetModeFailed};
    pub const Error = OpenError || GetModeError || SetSizeError;

    pub fn open(size: winsize) OpenError!Pty { ... }
    pub fn getMode(self: Pty) GetModeError!Mode { ... }
};
```

Each method declares its own error set. Module `Error` is the union. Callers see exactly what can fail.

### Result Union with Error Payloads (Bun)

```zig
pub fn Result(comptime T: type, comptime E: type) type {
    return union(enum) {
        ok: T,
        err: E,
        pub inline fn asErr(this: *const @This()) ?E {
            if (this.* == .err) return this.err;
            return null;
        }
    };
}
```

Unlike Zig error sets, attaches arbitrary context. Inline unwrapping. Compiler enforces exhaustive matching.

### Comptime Layout Invariants (TigerBeetle)

```zig
const TransferPending = extern struct {
    timestamp: u64,
    status: TransferPendingStatus,
    padding: [7]u8 = @splat(0),

    comptime {
        assert(@sizeOf(TransferPending) == 16);
        assert(stdx.no_padding(TransferPending));
    }
};
```

Catches struct layout bugs at compile time. Ensures deterministic serialization (no implicit padding). Essential for wire protocols and disk formats.

---

## Platform Abstraction

### OS-Specific Type Selection (Ghostty)

```zig
pub const Pty = switch (builtin.os.tag) {
    .windows => WindowsPty,
    .ios => NullPty,
    else => PosixPty,
};
```

Single type at module level. Callers don't care which impl they get. Platform code isolated.

### Module Facade with Conditional Exports (Ghostty)

```zig
// os/main.zig — platform-agnostic facade
pub const getenv = env.getenv;
pub const setenv = env.setenv;
pub const TempDir = @import("TempDir.zig");

test {
    if (comptime builtin.os.tag == .linux) _ = kernel_info;
    if (comptime builtin.os.tag.isDarwin()) _ = macos;
}
```

Consumer: `const os = @import("os");` then `os.getenv(...)`. Submodules hidden. Platform-specific tests compiled only for their target OS.

### macOS Objective-C Bridge (Ghostty)

```zig
const objc = @import("objc");

pub fn isAtLeastVersion(major: i64, minor: i64, patch: i64) bool {
    const info = objc.getClass("NSProcessInfo").?.msgSend(
        objc.Object, objc.sel("processInfo"), .{},
    );
    return info.msgSend(bool, objc.sel("isOperatingSystemAtLeastVersion:"), .{
        NSOperatingSystemVersion{ .major = major, .minor = minor, .patch = patch },
    });
}
```

Zig handles memory/ownership, ObjC message sends for macOS APIs. Error sets combine allocator + domain errors.

---

## C Interop

### Opaque Type Wrapper with RAII (Ghostty)

```zig
pub const IOSurface = opaque {
    pub fn init(properties: Properties) Allocator.Error!*IOSurface {
        var dict = try foundation.Dictionary.create(...);
        defer dict.release();
        return @ptrFromInt(@intFromPtr(c.IOSurfaceCreate(@ptrCast(dict))))
            orelse return error.OutOfMemory;
    }

    pub fn deinit(self: *IOSurface) void {
        _ = c.IOSurfaceSetPurgeable(@ptrCast(self), c.kIOSurfacePurgeableEmpty, null);
        foundation.CFRelease(self);
    }
};
```

Opaque wraps C types. Safe ownership: `init/deinit` pair, RAII via defer. Type conversions only at boundary.

### Packed Struct for C Bitfields (Ghostty)

```zig
pub const MTLResourceOptions = packed struct(c_ulong) {
    cpu_cache_mode: CPUCacheMode = .default,
    storage_mode: StorageMode,
    hazard_tracking_mode: HazardTrackingMode = .default,
    _pad: @Type(.{ .int = .{ .signedness = .unsigned, .bits = @bitSizeOf(c_ulong) - 10 } }) = 0,

    pub const StorageMode = enum(u4) { shared = 0, managed = 1, private = 2, memoryless = 3 };
};
```

Packed struct with nested enums matches C layout exactly. Compiler handles bit packing. No manual shifts.

---

## Comptime Patterns

### Conditional Callback via @hasDecl (Ghostty)

```zig
pub fn put(self: *Self, key: K, value: V) ?KV {
    // ... evict logic ...
    if (comptime @hasDecl(Context, "evicted"))
        self.context.evicted(evicted.key, evicted.value);
    return evicted;
}
```

Optional interface methods without stubs. Callback only compiled in if present.

### Module-Level Comptime Assertions (TigerBeetle)

```zig
comptime {
    assert(std.math.isPowerOfTwo(bucket_count));
    assert(constants.message_size_max % constants.sector_size == 0);
}
```

Validate generic parameters and alignment requirements at compile time. No runtime cost.

### EnumUnionType — Generate Union from Enum (TigerBeetle)

```zig
pub fn EnumUnionType(
    comptime Enum: type,
    comptime TypeForVariant: fn (comptime variant: Enum) type,
) type {
    var fields: [std.enums.values(Enum).len]std.builtin.Type.UnionField = undefined;
    for (std.enums.values(Enum), 0..) |variant, i| {
        fields[i] = .{
            .name = @tagName(variant),
            .type = TypeForVariant(variant),
            .alignment = @alignOf(TypeForVariant(variant)),
        };
    }
    return @Type(.{ .@"union" = .{ .layout = .auto, .fields = &fields, .decls = &.{}, .tag_type = Enum } });
}
```

Generates variant-specific message types. Eliminates boilerplate union definitions. Used for protocol dispatch.

### Length-Indexed Comptime String Map (Bun)

```zig
const precomputed = comptime blk: {
    @setEvalBranchQuota(99999);
    var sorted: [kvs.len]KV = undefined;
    // sort by length, then alphabetically
    std.sort.pdq(KV, &sorted, {}, lenAsc);

    var len_indexes: [max_len + 1]usize = undefined;
    // ... build index: length -> start position
    break :blk .{ .sorted = sorted, .len_indexes = len_indexes, .min_len = min_len, .max_len = max_len };
};

pub fn get(key: []const u8) ?V {
    if (key.len < precomputed.min_len or key.len > precomputed.max_len) return null;
    const start = precomputed.len_indexes[key.len];
    for (precomputed.sorted[start..]) |kv| {
        if (kv.key.len != key.len) break;
        if (std.mem.eql(u8, kv.key, key)) return kv.value;
    }
    return null;
}
```

O(1) length check eliminates most misses. Binary search only among same-length keys. Entire map computed at compile time. Used for keyword tables, HTTP headers.

### Comptime Type Specialization (Bun)

```zig
pub fn NewLexer(comptime json_options: JSONOptions) type {
    return struct {
        const is_json = json_options.is_json;
        const JSONBool = if (is_json) bool else void;

        // if (is_json) branches eliminated at compile time
        // JSON lexer and JS lexer compiled as separate code
    };
}
```

Zero-cost branch elimination. Each specialization is a distinct type with no runtime dispatch.

### Comptime Type Validation (Bun)

```zig
pub fn banFieldType(comptime Container: type, comptime T: type) void {
    comptime {
        for (std.meta.fields(Container)) |field| {
            if (field.type == T)
                @compileError("Field of type " ++ @typeName(T) ++ " not allowed");
        }
    }
}
```

Enforce struct invariants at compile time (e.g. ban raw pointers in AST nodes).

---

## String Optimization

### Small String Optimization (Bun)

```zig
pub const SmolStr = packed struct(u128) {
    __len: u32,
    cap: u32,
    __ptr: [*]u8,

    pub const Inlined = packed struct(u128) {
        data: u120,   // 15 bytes inline
        __len: u7,
        _tag: u1,     // 1 = inlined
        const max_len: comptime_int = 15;
    };

    pub fn isInlined(this: *const SmolStr) bool {
        return @intFromPtr(this.__ptr) & 0x8000000000000000 != 0;
    }
};
```

15-byte inline storage for short strings (URLs, identifiers, method names). Tagged pointer: high bit = inline flag. Same 16-byte footprint whether inlined or heap-allocated.

---

## Testing

### Snapshot Testing (TigerBeetle)

```zig
test "prng distribution" {
    var prng = from_seed(92);
    var distribution: [8]u32 = @splat(0);
    for (0..1000) |_| distribution[prng.next() % 8] += 1;

    try snap(@src(),
        \\{ 134, 134, 117, 121, 117, 128, 131, 118 }
    ).diff_fmt("{d}", .{distribution});
}
```

Detect regressions in deterministic outputs. `snap` captures expected, `diff_fmt` shows diffs on failure.

### Edge-Biased Fuzz Generation (TigerBeetle)

```zig
pub fn int_edge_biased(prng: *PRNG, T: anytype) T {
    const bits = @typeInfo(T).int.bits;
    const bias_to = prng.range_inclusive(T, 0, bits * 2);
    if (bias_to > bits) return prng.int(T);  // ~50% uniform
    // ~50% biased toward power-of-2 boundaries +/- 8
    const center: T = if (bias_to == bits) std.math.maxInt(T)
        else std.math.pow(T, 2, bias_to);
    return prng.range_inclusive(T, center -| 8, center +| 8);
}
```

50/50 split: uniform vs edge-case biased. Targets min/max/power-of-2 boundaries. Finds overflow and boundary condition bugs.

### VOPR — Verification of Protocols via Randomized Testing (TigerBeetle)

```zig
pub fn main(allocator: Allocator, args: FuzzArgs) !void {
    var prng = stdx.PRNG.from_seed(args.seed);
    for (0..args.events_max orelse 50_000) |_| {
        const operation = prng.enum_uniform(StateMachine.Operation);
        const size = build_batch(&prng, operation, request_buffer);
        if (state_machine.input_valid(operation, request_buffer[0..size])) {
            context.prepare(operation, request_buffer[0..size]);
            _ = context.execute(op, operation, request_buffer[0..size], reply_buffer);
        }
    }
}
```

Fuzzes state machines with random operations and batch configurations. Seeded for reproducible failures. Varies batch counts and sizes.

### Conditional Test Compilation (Ghostty)

```zig
test {
    _ = i18n;
    _ = path;
    if (comptime builtin.os.tag == .linux) _ = kernel_info;
    if (comptime builtin.os.tag.isDarwin()) _ = macos;
}
```

Module-level test references all submodules. Platform-specific tests only compile for their target.

---

## Performance

### Inline Custom Assert (Ghostty)

```zig
pub const inlineAssert = switch (builtin.mode) {
    .Debug => std.debug.assert,
    .ReleaseSmall, .ReleaseSafe, .ReleaseFast => (struct {
        inline fn assert(ok: bool) void { if (!ok) unreachable; }
    }).assert,
};
```

Stdlib `assert` sometimes doesn't optimize out in ReleaseFast. Custom inline version with `unreachable` helps the compiler. Saves 15-20% in tight loops.

### Thread-Local Object Pool (Bun)

```zig
const HashMapPool = struct {
    threadlocal var list: LinkedList = undefined;
    threadlocal var loaded: bool = false;

    pub fn get(_: Allocator) *LinkedList.Node {
        if (loaded) {
            if (list.popFirst()) |node| {
                node.data.clearRetainingCapacity();
                return node;
            }
        }
        return default_allocator.create(LinkedList.Node) catch unreachable;
    }

    pub fn release(node: *LinkedList.Node) void {
        if (loaded) { list.prepend(node); return; }
        list = LinkedList{ .first = node };
        loaded = true;
    }
};
```

Per-thread reuse without contention. `clearRetainingCapacity()` resets without deallocating. Lazy init via `loaded` flag.

### Seeded PRNG without Floating Point (TigerBeetle)

```zig
// Custom PRNG avoids:
// - floating point (non-deterministic across platforms)
// - stdlib API churn
// - Lemire's algorithm for unbiased bounded integers

pub fn int_inclusive(prng: *PRNG, Int: anytype, max: Int) Int {
    var x = prng.int(Int);
    var m = math.mulWide(Int, x, less_than);
    var l: Int = @truncate(m);
    if (l < less_than) {
        var t = -%less_than;  // rejection sampling threshold
        while (l < t) { x = prng.int(Int); m = math.mulWide(Int, x, less_than); l = @truncate(m); }
    }
    return @intCast(m >> bits);
}
```

No floating point ensures cross-platform determinism. Lemire's algorithm: unbiased without modulo.

### Labeled Union State Machine (TigerBeetle)

```zig
pub const CommitStage = union(enum) {
    idle,
    start,
    prefetch,
    execute,
    checkpoint_data: CheckpointDataProgress,
    checkpoint_superblock,

    const CheckpointDataProgress = std.enums.EnumSet(CheckpointData);
};
```

Exhaustive pattern matching prevents invalid transitions. Nested enum sets for parallel subtask tracking.
