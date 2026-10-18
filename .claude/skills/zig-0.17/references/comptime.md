# Comptime Reference

Zig's comptime system enables metaprogramming through partial evaluation and type reflection. This reference covers comptime fundamentals, type reflection, and common techniques.

## Table of Contents

- [Fundamentals](#fundamentals)
- [Type Reflection](#type-reflection)
- [Loop Variants](#loop-variants)
- [Branch Elimination](#branch-elimination)
- [Type Generation](#type-generation)
- [Limitations](#limitations)

---

## Fundamentals

### Comptime Parameters

Values that must be known at compile time. Types are always comptime.

```zig
fn max(comptime T: type, a: T, b: T) T {
    return if (a > b) a else b;
}

const result = max(i32, 5, 10);  // T=i32 known at compile time
```

A `comptime` parameter means:
- At the callsite, the value must be known at compile time
- In the function definition, the value is comptime-known

### Comptime Variables

Variables whose loads/stores happen at compile time.

```zig
comptime var i: usize = 0;
inline while (i < 3) : (i += 1) {
    // i is comptime-known each iteration
}
```

### Comptime Blocks

Force expression evaluation at compile time.

```zig
const primes = comptime blk: {
    var result: [10]u32 = undefined;
    // ... compute primes ...
    break :blk result;
};

comptime {
    // All code here runs at compile time
    if (@sizeOf(MyStruct) > 64) @compileError("too large");
}
```

### Container-Level Comptime

Top-level declarations are implicitly comptime.

```zig
// These are computed at compile time automatically
const lookup_table = generateTable();
const config = parseConfig(@embedFile("config.json"));
```

---

## Type Reflection

### Builtins

| Builtin | Purpose |
|---------|---------|
| `@typeInfo(T)` | Get type metadata as `std.lang.Type` |
| `@Int`, `@Struct`, `@Union`, `@Enum`, `@Pointer`, `@Fn`, `@Tuple` | Create a type (inverse of `@typeInfo`; `@Type` is gone since 0.16) |
| `@TypeOf(expr)` | Get type of expression |
| `@typeName(T)` | Get type name as `[:0]const u8` |
| `@hasDecl(T, name)` | Check if type has a `pub` declaration (0.17: non-`pub` decls are invisible) |
| `@hasField(T, name)` | Check if type has field |
| `@field(value, name)` | Access field by comptime-known name |

### Accessing Type Info for Keywords

Use `@"keyword"` syntax because `union`, `struct`, `enum` are reserved:

```zig
const union_info = @typeInfo(MyUnion).@"union";
const struct_info = @typeInfo(MyStruct).@"struct";
const enum_info = @typeInfo(MyEnum).@"enum";
const fn_info = @typeInfo(@TypeOf(myFn)).@"fn";
```

### Common Type Info Fields

**Struct:**
```zig
const info = @typeInfo(MyStruct).@"struct";
// info.field_names: []const [:0]const u8
// info.field_types: []const type
// info.field_attrs: []const FieldAttributes
// info.decl_names: []const [:0]const u8
// info.is_tuple: bool
```

**Union:**
```zig
const info = @typeInfo(MyUnion).@"union";
// info.tag_type: ?type (null if untagged)
// info.field_names, info.field_types, info.field_attrs
// info.layout: .auto, .@"extern", .@"packed"
```

**Enum:**
```zig
const info = @typeInfo(MyEnum).@"enum";
// info.tag_type: type (backing integer)
// info.field_names, info.field_values
// info.mode: .exhaustive or .nonexhaustive
```

### Creating Union Values with Comptime Tag

Use `@unionInit` when the tag is comptime-known:

```zig
const Action = union(enum) {
    move: struct { x: i32, y: i32 },
    jump,
    attack: u32,
};

// Create union with comptime-known field name
const action = @unionInit(Action, "move", .{ .x = 10, .y = 20 });
```

---

## Loop Variants

### comptime for

Full compile-time evaluation. Can use `break` to return values. Cannot reference runtime values.

```zig
// Return value from comptime loop
fn hasField(comptime T: type, comptime name: []const u8) bool {
    const names = @typeInfo(T).@"struct".field_names;
    return comptime for (names) |n| {
        if (std.mem.eql(u8, n, name)) break true;
    } else false;
}

// Computation in comptime block
fn sumComptime(comptime values: []const i32) i32 {
    // `comptime { ...; return x; }` does NOT compile when called from runtime code
    // ("function called at runtime cannot return value at comptime"); use a labeled block.
    return comptime blk: {
        var sum: i32 = 0;
        for (values) |v| sum += v;
        break :blk sum;
    };
}
```

**Verified in stdlib:** `std/Build.zig`

### inline for

Loop unrolling with code generation. Body is duplicated per iteration. Can reference runtime values. Cannot use `break` to return values.

```zig
fn printFields(value: anytype) void {
    const T = @TypeOf(value);
    const names = @typeInfo(T).@"struct".field_names;

    // Each iteration generates separate code
    inline for (names) |name| {
        const field_value = @field(value, name);
        std.debug.print("{s} = {any}\n", .{ name, field_value });
    }
}

// Runtime comparison via unrolling
fn eqlAny(comptime T: type, a: T, b: T) bool {
    const names = @typeInfo(T).@"struct".field_names;
    inline for (names) |name| {
        if (@field(a, name) != @field(b, name)) {
            return false;  // Runtime return
        }
    }
    return true;
}
```

**Verified in stdlib:** `std/meta.zig`, `compiler_rt/fmax.zig`

### Decision Table

| Need | Use | Reason |
|------|-----|--------|
| Return value from loop | `comptime for` | Only comptime allows `break` with value |
| Access runtime values in body | `inline for` | Comptime can't see runtime |
| Type-level computation only | `comptime for` | Clearer intent, no code gen |
| Generate code per iteration | `inline for` | Each iteration = separate code |
| Normal runtime iteration | regular `for` | No unrolling needed |

---

## Branch Elimination

Comptime-known conditions eliminate dead branches entirely—no runtime cost.

### Basic Elimination

```zig
fn process(comptime T: type, value: T) T {
    if (T == bool) {
        return !value;  // Only exists for bool
    } else {
        return value + 1;  // Only exists for integers
    }
}
```

### Platform-Specific Code

```zig
const builtin = @import("builtin");

// Branch on the target at comptime; only the taken branch is compiled.
const page_size_hint = if (builtin.target.os.tag == .macos and builtin.target.cpu.arch == .aarch64)
    16 * 1024
else
    4 * 1024;

// Reading a big-endian integer: use std.mem.readInt. A hand-rolled `@bitCast` of the byte
// array plus a byte swap on little-endian hosts is wrong on big-endian targets in 0.17,
// where an array `@bitCast` is defined as little-endian on every target.
pub fn readIntBig(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, bytes[0..@divExact(@bitSizeOf(T), 8)], .big); // u24 reads 3 bytes, not @sizeOf = 4
}
```

### Propagating Across Functions

Use `inline fn` to propagate comptime conditions to call sites:

```zig
// WITHOUT inline: branch exists at runtime
fn maybeLog(comptime enabled: bool, msg: []const u8) void {
    if (enabled) std.debug.print("{s}\n", .{msg});
}

// WITH inline: branch eliminated at each call site
inline fn maybeLogInline(comptime enabled: bool, msg: []const u8) void {
    if (comptime enabled) std.debug.print("{s}\n", .{msg});
}

pub fn example() void {
    maybeLogInline(false, "debug");  // Entire call eliminated
    maybeLogInline(true, "important");  // Only this generates code
}
```

**Verified in stdlib:** `std/math.zig`, `std/log.zig`

---

## Type Generation

### Returning Types from Functions

```zig
fn Pair(comptime A: type, comptime B: type) type {
    return struct {
        first: A,
        second: B,

        const Self = @This();

        pub fn swap(self: Self) Pair(B, A) {
            return .{ .first = self.second, .second = self.first };
        }
    };
}

const IntStr = Pair(i32, []const u8);
var p: IntStr = .{ .first = 42, .second = "hello" };
```

### Generating Union Subsets

Generate a subset union type from a larger union:

```zig
pub fn Subset(comptime T: type, comptime fields: []const std.meta.FieldEnum(T)) type {
    const source_info = @typeInfo(T).@"union";
    var names: [fields.len][:0]const u8 = undefined;
    var types: [fields.len]type = undefined;
    var attrs: [fields.len]std.lang.Type.Union.FieldAttributes = undefined;

    for (fields, 0..) |field_enum, i| {
        const field_name = @tagName(field_enum);
        for (source_info.field_names, source_info.field_types, source_info.field_attrs) |name, FieldT, attr| {
            if (std.mem.eql(u8, name, field_name)) {
                names[i] = name;
                types[i] = FieldT;
                attrs[i] = attr;
                break;
            }
        }
    }

    // 0.17: @Union replaces @Type(.{ .@"union" = ... })
    const Bare = @Union(source_info.layout, null, &names, &types, &attrs);
    return @Union(source_info.layout, std.meta.FieldEnum(Bare), &names, &types, &attrs);
}
```

### Converting Between Union Types

Use `inline else` to capture tag at comptime:

```zig
/// Convert subset to full union type.
pub fn toFull(comptime Full: type, subset: anytype) Full {
    return switch (subset) {
        inline else => |payload, tag| @unionInit(Full, @tagName(tag), payload),
    };
}

/// Try to narrow full union to subset type.
pub fn toSubset(comptime Sub: type, full: anytype) ?Sub {
    const subset_names = @typeInfo(Sub).@"union".field_names;
    return switch (full) {
        inline else => |payload, tag| {
            inline for (subset_names) |sf_name| {
                if (comptime std.mem.eql(u8, sf_name, @tagName(tag))) {
                    return @unionInit(Sub, sf_name, payload);
                }
            }
            return null;
        },
    };
}
```

**Verified in stdlib:** `std/meta.zig`, `std/json/static.zig`

---

## Limitations

Zig's comptime is deliberately constrained for cross-compilation safety and code clarity.

### No Host Architecture Detection

```zig
// This reflects TARGET, not host
const is_64bit = comptime @sizeOf(usize) == 8;

// Use build.zig for host detection
// build.zig runs as a program and can query host
```

### No String-to-Code Evaluation

```zig
// NOT POSSIBLE
const code = "x + y";
const result = @eval(code);  // No such builtin

// Alternative: Parse strings to data structures at comptime
const query = comptime sql.parse("SELECT * FROM users");
```

### No Runtime Type Information

```zig
// This works - type known at comptime
fn getTypeName(value: anytype) []const u8 {
    return @typeName(@TypeOf(value));
}

// NOT POSSIBLE - can't turn runtime string into type
fn typeFromName(name: []const u8) type { ... }
```

### No I/O at Comptime

```zig
// NOT POSSIBLE
const config = comptime std.Io.Dir.cwd().readFile(io, "config.json", &buf);

// Alternatives:
const config = @embedFile("config.json");  // Static embedding
// Or use build.zig which runs as a normal program
```

### No Dynamic Method Injection

```zig
// This works - methods defined in type
fn Pair(comptime A: type, comptime B: type) type {
    return struct {
        first: A,
        second: B,
        pub fn swap(self: @This()) Pair(B, A) { ... }
    };
}

// NOT POSSIBLE - can't add methods to existing types
fn addMethod(comptime T: type, comptime name: []const u8, impl: anytype) type { ... }
```

### Summary Table

| Want to do | Comptime? | Alternative |
|------------|-----------|-------------|
| Type reflection | Yes | `@typeInfo`, `@TypeOf` |
| Generate types | Yes | Return struct from function |
| Add methods to types | No | Define in type definition |
| Read files | No | `@embedFile` or build.zig |
| Syscalls | No | build.zig runs as program |
| Parse strings to code | No | Parse to data structures |
| Host detection | No | Build system queries |

### Design Rationale

These constraints ensure:
1. **Cross-compilation works** - comptime sees target, not host
2. **Code is readable** - no hidden code generation
3. **Builds are reproducible** - no I/O side effects
4. **All API is visible** - no dynamic method injection
