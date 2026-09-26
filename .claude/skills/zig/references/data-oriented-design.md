# Data-Oriented Design in Zig

**Load when designing data structures for hot paths, large collections, compilers/parsers, ECS, or any code where memory footprint drives performance.**

Distilled from Andrew Kelly's "Practical Data-Oriented Design" talk and applied to the Zig compiler (self-hosted). The core thesis: **the CPU is fast, main memory is slow; the single most impactful optimization is making the structs you have *the most of* in memory smaller, so more of them fit in a cache line and you take fewer cache misses.**

## Mental Model

```
L1 (~KB, fast) → L2 → L3 → RAM (huge, ~order of magnitude slower per level)
```

- Every memory access goes through a cache line (typically **64 bytes**). The only goal is to **avoid cache misses** (evicting a line to fetch another).
- **Computation is cheaper than memory.** Integer math — including multiplication — is faster than an L1 read. Do **not** memoize values you can recompute; memoization that touches memory can be a *slowdown*.
- **`malloc`/heap allocation can trigger a kernel call** (one of the slowest non-I/O operations). Prefer arenas, pools, and index-based storage in hot paths. See [std-allocators.md](std-allocators.md).
- A `bool` is 1 bit of information but, naively stored in a struct, can cost up to 8 bytes after alignment.

## The One Trick

Find the struct type you have **the most instances of** in memory (large arrays of homogeneous objects), then **shrink each instance**. That is ~80% of the win.

## Struct Layout: Size, Alignment, Padding

Size = sum of field sizes + padding inserted to satisfy each field's alignment and the struct's overall alignment (= alignment of its largest field).

| Struct | Size | Why |
|---|---|---|
| `struct { a: u32, b: bool }` | **8** | 4 + 1, then padded to 8 (struct align = 4) |
| `struct { a: u32, b: u64, c: u32 }` | **24** | u32→pad→u64→u32→pad |
| `struct { b: u64, a: u32, c: u32 }` | **16** | same fields, reordered — no interior padding |
| add a `bool` to the 16-byte one | **24** | one bool costs 8 bytes here |

**Rules of thumb:**
- The default (`auto`) layout **already reorders fields freely to minimize padding** — you do **not** need to hand-order them, and you cannot rely on declaration order. Verified on 0.15.2: `struct { a: []const u8, x: bool, b: []const u8, y: bool, c: []const u8, z: bool }` lays out as `a=0, b=16, c=32, x=48, y=49, z=50` (slices packed first, bools grouped at the tail) → 56 B, not the 72 B declaration order would give. So "order fields large-first" / "group your bools" is **a no-op the compiler does for you**; don't waste edits on it.
- Verify with `@sizeOf(T)`, `@alignOf(T)`, `@offsetOf(T, "field")` at comptime.
- To **guarantee** a layout (FFI, on-disk formats, MMIO), use `extern struct` (C ABI order) or `packed struct` (bit-packed, backed by an integer, e.g. `packed struct { alive: bool, kind: u3, hp: u12 }`). These are the only layouts whose field order is fixed.
- Shrinking a struct is still about *removing/narrowing* fields (drop derivable data, box a rare large variant, `u32` not `u64`, indices not pointers) — not about reordering, which `auto` handles.

## The Six Techniques (most to least common)

### 1. Indexes instead of pointers
Store objects in an `ArrayList`/`MultiArrayList`; refer to them with a `u32` index, not `*T`.
- **Halves** pointer size on 64-bit (8→4) and lowers alignment 8→4, so neighboring fields pad less.
- Indexes stay valid across reallocation (pointers don't) and serialize trivially.

⚠️ **Type-safety cost:** Zig has no distinct integer types, so raw `u32` handles are easy to mix up. Wrap them:

```zig
// Newtype handle — distinct type, still a u32 in memory.
const MonsterId = enum(u32) { _ };          // non-exhaustive enum as opaque handle
// or
const NodeIndex = enum(u32) { none = std.math.maxInt(u32), _ };

fn get(list: *const MonsterList, id: MonsterId) *Monster {
    return &list.items[@intFromEnum(id)];
}
```
Search "handles are the better pointers" (Andre Weissflug / Floooh) for the full pattern.

### 2. Store booleans out of band
Don't keep `alive: bool` in a hot struct. Keep **two arrays** (alive / dead); the boolean becomes "which array am I in."
- Iterating only the alive array means **no load and no branch** on the flag → fewer cache misses.
- Generalizes to any low-entropy enum that partitions the set.

### 3. Struct-of-Arrays instead of Array-of-Structs
Use **[std.MultiArrayList](std-multi-array-list.md)** — same API, fields stored in parallel arrays.
- Eliminates inter-element padding (each field array is densely packed by type).
- Lets you scan one field across all elements without pulling unrelated fields into cache.
- Talk result: 10k objects 160 KB → 91 KB from a ~5-character type change.

```zig
var monsters: std.MultiArrayList(Monster) = .empty;
try monsters.append(gpa, .{ .pos = p, .kind = .human });
const kinds = monsters.items(.kind);   // dense []Kind, no padding
```

### 4. Store sparse data in hash maps
If a field is empty/default for most instances (rare inventory, optional attribute), pull it out of the struct into a `HashMap(Index, Value)` keyed by the object's index.
- Talk result: 10k objects 366 KB → 198 KB with only 10% of objects carrying the field.
- Pick the split by your **observed distribution** (e.g. most carry exactly one item → store one inline, overflow to a map). See [std-array-hash-map.md](std-array-hash-map.md).

### 5. Encodings instead of polymorphism / fat tagged unions
A plain tagged union sizes every element to the largest variant ("paying for humans even on the bees"). Polymorphism (base + extensions) helps, but **multiple encoding tags** win: dedicate tags to *common combinations of state*, so boolean flags and rare attributes dissolve into the tag.
- Talk progression for one element: 32 (tagged union) → 24 (OOP/base struct) → **17 bytes** (encoding), tuned to the data's distribution.
- Each variant can repurpose shared fields (e.g. a generic `lhs`/`rhs` pair whose meaning depends on the tag) — this is exactly how Zig's own AST/ZIR encode nodes.

```zig
const Node = struct {
    tag: Tag,         // many encodings, not one canonical form
    main_token: u32,
    data: Data,       // union of small fixed payloads, meaning per-tag

    const Tag = enum(u8) {
        var_decl_simple, var_decl_typed, var_decl_aligned, // 3 encodings of "var decl"
        if_simple, if_else,
        while_simple, while_cont,
        // ...
    };
};
```

### 6. Constrain ranges and stop memoizing derivable data
- "We only support source files ≤ 4 GiB" → offsets become `u32`, not `u64`. State your limits and exploit them.
- Don't store what you can recompute cheaply: line/column from a byte offset, a token's end from its start (a keyword's length is known from its tag), parsed integer/string-literal values (parse later, same cost, smaller token).

## Case Study Results (self-hosted Zig compiler)

The pipeline's intermediate data (source→tokens→AST→ZIR→…→machine code) is "just data the compiler picks the layout of" — so DoD applies directly:

| Structure | Before | After | Technique |
|---|---|---|---|
| Token | 64 B | **5 B** | offset + tag only; recompute line/col/end; defer literal parsing |
| AST node | 120 B | **15.6 B avg** | encoding + SoA; lazy line/col |
| ZIR instruction | 54 B | **20.3 B avg** | encoding; u32 source-loc indexes; index refs |

- AST+token rework alone: **−22% wall-clock**; ZIR rework on top: **−39% wall-clock**.
- Bonus: shrinking everything turns the IR into **plain parallel arrays** (tag + common data + extra + string table) → save/load the on-disk cache in **one `writev`/`readv` syscall**, and the per-file front-end stage is embarrassingly parallel (8.9M lines/sec on a thread pool). See [std-multi-array-list.md](std-multi-array-list.md) and [std-thread.md](std-thread.md).

## Anti-Patterns (red flags in your own code)

- `u64` where the value's real range fits `u32` (or smaller). *(Field **position/order** is NOT a smell — `auto` layout reorders to pack padding for you; only field **size and count** matter.)*
- Storing what's cheap to recompute (line/col, end positions, keyword lengths, parsed literals).
- `*T` where a `u32` index into an array would do.
- Array-of-Structs for a hot homogeneous collection instead of `MultiArrayList`.
- A fat tagged union sized to its largest variant when most instances are small.

## Related References

- **[std.MultiArrayList](std-multi-array-list.md)** — SoA container (techniques 3, 5)
- **[std.ArrayHashMap](std-array-hash-map.md)** / **[std.HashMap](std-hashmap.md)** — sparse out-of-band storage (technique 4)
- **[std.heap / allocators](std-allocators.md)** — arenas/pools to avoid per-object heap calls
- **[Production Patterns](production-patterns.md)** — cache-line aligned SoA, SmolStr SSO, pre-allocated pools from Bun/Ghostty/TigerBeetle
- **[std.simd](std-simd.md)** — once data is SoA, fields scan well under SIMD
