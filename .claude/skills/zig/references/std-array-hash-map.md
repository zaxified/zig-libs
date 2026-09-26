# std.ArrayHashMap (0.16)

A hash map that preserves insertion order and stores keys/values in contiguous arrays. Combines hash table lookup with array-like iteration.

**0.16 change:** the *managed* wrappers (`std.ArrayHashMap`, `std.AutoArrayHashMap`, `std.StringArrayHashMap` — the ones that store their own allocator) are **gone**. Only the unmanaged generics remain, and even the `...Unmanaged` names in `std.zig` (`std.ArrayHashMapUnmanaged`, `std.AutoArrayHashMapUnmanaged`, `std.StringArrayHashMapUnmanaged`) are marked deprecated in favor of calling `std.array_hash_map.Custom` / `.Auto` / `.String` directly. Every map is allocator-less: initialize with `.empty`, and pass `gpa` to any method that can grow the map (`put`, `getOrPut`, `ensureTotalCapacity`, `deinit`, ...).

## When to Use

- Need deterministic iteration order (insertion order)
- Need array-style access to keys/values
- JSON object preservation
- When iteration performance matters more than removal performance

## Variants

| Type | Description |
|------|-------------|
| `std.array_hash_map.Auto(K, V)` | Auto-hashing for common key types |
| `std.array_hash_map.Custom(K, V, Ctx, store_hash)` | Custom hash/equal context |
| `std.array_hash_map.String(V)` | String keys |

## Basic Usage

```zig
const std = @import("std");

var map: std.array_hash_map.Auto(u32, []const u8) = .empty;
defer map.deinit(allocator);

// Insert
try map.put(allocator, 1, "one");
try map.put(allocator, 2, "two");
try map.put(allocator, 3, "three");

// Lookup
if (map.get(2)) |value| {
    std.debug.print("2 = {s}\n", .{value});
}

// Check existence
if (map.contains(1)) {
    // key exists
}
```

## Insertion Order Preserved

```zig
try map.put(allocator, 10, "ten");
try map.put(allocator, 5, "five");
try map.put(allocator, 15, "fifteen");

// Iteration is in insertion order: 10, 5, 15
var it = map.iterator();
while (it.next()) |entry| {
    std.debug.print("{}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
}
```

## Array Access

```zig
// Direct access to underlying arrays
const keys = map.keys();     // []K slice of all keys
const values = map.values(); // []V slice of all values

// Access by index
for (keys, values) |k, v| {
    std.debug.print("{}: {s}\n", .{ k, v });
}
```

## Removal (Two Options)

```zig
// O(1) removal - swaps with last element, changes order. Returns whether a key was removed.
_ = map.swapRemove(key);

// O(n) removal - shifts elements, preserves order. Returns whether a key was removed.
_ = map.orderedRemove(key);

// Fetch and remove
if (map.fetchSwapRemove(key)) |kv| {
    std.debug.print("removed {}: {s}\n", .{ kv.key, kv.value });
}
```

## Get or Put

```zig
// Get existing or insert new
const result = try map.getOrPut(allocator, key);
if (!result.found_existing) {
    result.value_ptr.* = "new_value";
}

// Get or put with default value
const result2 = try map.getOrPutValue(allocator, key, "default");
```

## Index-Based Operations

```zig
// Get index of key
if (map.getIndex(key)) |idx| {
    // Remove by index
    map.swapRemoveAt(idx);
    // or
    map.orderedRemoveAt(idx);
}
```

## Capacity Management

```zig
try map.ensureTotalCapacity(allocator, 100);
try map.ensureUnusedCapacity(allocator, 10);

const cap = map.capacity();
const len = map.count();

map.clearRetainingCapacity();
map.clearAndFree(allocator);
```

## String Keys

```zig
var map: std.array_hash_map.String(i32) = .empty;
defer map.deinit(allocator);

try map.put(allocator, "apple", 1);
try map.put(allocator, "banana", 2);

// Keys are stored by reference, not copied
// Make sure string lifetime exceeds map usage
```

## Custom Context

```zig
const CaseInsensitiveContext = struct {
    pub fn hash(_: @This(), key: []const u8) u32 {
        var h: u32 = 0;
        for (key) |c| {
            h = h *% 31 +% std.ascii.toLower(c);
        }
        return h;
    }
    pub fn eql(_: @This(), a: []const u8, b: []const u8, _: usize) bool {
        return std.ascii.eqlIgnoreCase(a, b);
    }
};

var map: std.array_hash_map.Custom(
    []const u8,
    i32,
    CaseInsensitiveContext,
    true,  // store_hash for better performance
) = .empty;
defer map.deinit(allocator);

try map.put(allocator, "Hello", 1);
_ = map.get("HELLO");  // finds it! (CaseInsensitiveContext is zero-sized, so no *Context calls needed)
```

## Complete Example: Word Counter

```zig
const std = @import("std");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var counts: std.array_hash_map.String(u32) = .empty;
    defer counts.deinit(allocator);

    const words = [_][]const u8{ "apple", "banana", "apple", "cherry", "banana", "apple" };

    for (words) |word| {
        const result = try counts.getOrPut(allocator, word);
        if (result.found_existing) {
            result.value_ptr.* += 1;
        } else {
            result.value_ptr.* = 1;
        }
    }

    // Print in insertion order
    var it = counts.iterator();
    while (it.next()) |entry| {
        std.debug.print("{s}: {}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    // Output (insertion order):
    // apple: 3
    // banana: 2
    // cherry: 1
}
```

## Comparison with HashMap

| Feature | HashMap | ArrayHashMap |
|---------|---------|--------------|
| Lookup | O(1) | O(1) |
| Insert | O(1) amortized | O(1) amortized |
| swapRemove | O(1) | O(1) |
| orderedRemove | N/A | O(n) |
| Iteration order | Undefined | Insertion order |
| Key/value arrays | No | Yes |
| Memory layout | Scattered | Contiguous |

## Notes

- Iteration order equals insertion order
- `swapRemove`/`orderedRemove` return `bool` (whether something was removed), not the removed value — use `fetchSwapRemove` for that
- Use `store_hash=true` when `eql` is expensive
- Keys/values are stored in a `MultiArrayList`-like layout (cache-friendly)
- Pointer stability only guaranteed with pre-allocated capacity
- There is no managed (self-storing-the-allocator) variant in 0.16 — always pass `gpa` explicitly to mutating methods
