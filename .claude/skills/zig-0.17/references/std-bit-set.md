# std.bit_set

Densely stored sets of integers with efficient set operations (union, intersection, complement). Each integer gets a single bit.

## When to Use

- Track presence/absence of items from a known finite set
- Set operations (union, intersection, difference)
- Bit flags with variable size
- Compact storage when max value is known

## Variants

| Type | Size | Allocation |
|------|------|------------|
| `bit_set.Integer(N)` | Compile-time, N <= 128 | None (single integer) |
| `bit_set.Array(usize, N)` | Compile-time, any N | None (array) |
| `bit_set.Static(N)` | Compile-time | Auto-selects Integer or Array |
| `bit_set.Dynamic` | Runtime | Allocator (unmanaged, preferred) |
| `bit_set.DynamicManaged` | Runtime | Allocator (managed, deprecated) |

## Static Bit Set (Compile-Time Size)

```zig
const std = @import("std");

// Static auto-selects best implementation (was StaticBitSet before 0.17)
const Flags = std.bit_set.Static(64);

var flags: Flags = .empty;  // .full for all bits set (was initEmpty()/initFull())
flags.set(5);
flags.set(10);

if (flags.isSet(5)) {
    // bit 5 is set
}

flags.unset(5);
flags.toggle(10);

const count = flags.count();  // number of set bits
```

## Dynamic Bit Set (Runtime Size)

```zig
var bits = try std.bit_set.Dynamic.initEmpty(allocator, 1000);
defer bits.deinit(allocator);

bits.set(42);
bits.set(100);

// Resize dynamically
try bits.resize(allocator, 2000, false);  // false = new bits are 0
try bits.resize(allocator, 2000, true);   // true = new bits are 1

// Clone
var copy = try bits.clone(allocator);
defer copy.deinit(allocator);
```

## Set Operations

```zig
var a: Flags = .empty;
var b: Flags = .empty;
a.set(1); a.set(2);
b.set(2); b.set(3);

// In-place operations (modify a)
a.setUnion(b);        // a = a | b  (bits in either)
a.setIntersection(b); // a = a & b  (bits in both)
a.toggleSet(b);       // a = a ^ b  (flip bits that are in b)

// Return new set (pure functions)
const union_set = a.unionWith(b);
const intersection = a.intersectWith(b);
const xor_set = a.xorWith(b);
const diff = a.differenceWith(b);  // a - b
const comp = a.complement();        // ~a
```

## Comparison

```zig
if (a.eql(b)) {
    // same bits set
}

if (a.subsetOf(b)) {
    // all bits in a are also in b
}

if (a.supersetOf(b)) {
    // all bits in b are also in a
}
```

## Iteration

```zig
var flags: Flags = .empty;
flags.set(1); flags.set(5); flags.set(10);

// Iterate set bits (ascending order by default)
var it = flags.iterator(.{});
while (it.next()) |index| {
    std.debug.print("bit {} is set\n", .{index});
}

// Iterate unset bits
var unset_it = flags.iterator(.{ .kind = .unset });

// Reverse order
var rev_it = flags.iterator(.{ .direction = .reverse });
```

## Range Operations

```zig
// Set/unset a range of bits
flags.setRangeValue(.{ .start = 10, .end = 20 }, true);   // set bits 10-19
flags.setRangeValue(.{ .start = 10, .end = 20 }, false);  // unset bits 10-19
```

## Find Operations

```zig
// Find first/last set bit
if (flags.findFirstSet()) |index| {
    // index of lowest set bit
}

if (flags.findLastSet()) |index| {
    // index of highest set bit
}

// Find and toggle (atomic-like)
if (flags.toggleFirstSet()) |index| {
    // returns index and unsets the bit
}
```

## Toggle All

```zig
flags.toggleAll();  // flip every bit
```

## Unmanaged Dynamic BitSet

```zig
// For when you don't want to store the allocator
var bits: std.bit_set.Dynamic = .{};
try bits.resize(allocator, 100, false);
defer bits.deinit(allocator);

bits.set(50);
```

## Complete Example: Permission Flags

```zig
const std = @import("std");

const Permission = enum(u8) {
    read = 0,
    write = 1,
    execute = 2,
    delete = 3,
    admin = 4,
};

const Permissions = std.bit_set.Static(8);

fn hasPermission(perms: Permissions, p: Permission) bool {
    return perms.isSet(@backingInt(p));
}

fn grant(perms: *Permissions, p: Permission) void {
    perms.set(@backingInt(p));
}

fn revoke(perms: *Permissions, p: Permission) void {
    perms.unset(@backingInt(p));
}

pub fn main() void {
    var user_perms = Permissions.empty;
    grant(&user_perms, .read);
    grant(&user_perms, .write);

    const admin_perms = Permissions.full;

    // Check if user has all admin permissions
    if (user_perms.subsetOf(admin_perms)) {
        // user can do everything admin can (not in this case)
    }

    // Grant user all of admin's permissions
    user_perms.setUnion(admin_perms);
}
```

## Notes

- `bit_set.Static` is zero-allocation, copyable by value
- `bit_set.Dynamic` requires allocation, call `deinit(allocator)`
- `.full` is the set with all bits set, `.empty` the empty one (Static/Integer/Array; `Dynamic.initFull(allocator, n)` is unchanged)
- Iteration order is index order, not insertion order
- Use `std.enums.EnumSet` for enum-based bit flags
