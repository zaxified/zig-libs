# std.zon - ZON Parsing and Serialization

ZON ("Zig Object Notation") parsing and stringification in Zig 0.17.0. ZON's grammar is a subset of Zig's syntax.

## Table of Contents
- [ZON Format Overview](#zon-format-overview)
- [Parsing ZON](#parsing-zon)
- [Serializing to ZON](#serializing-to-zon)
- [Low-Level Serializer API](#low-level-serializer-api)
- [Supported Types](#supported-types)
- [Common Patterns](#common-patterns)

## ZON Format Overview

ZON is a data format using Zig's literal syntax:

```zig
// Example ZON file
.{
    .name = "my-project",
    .version = .{ 0, 1, 0 },
    .dependencies = .{
        .@"std-lib" = .{ .url = "https://...", .hash = "abc123" },
    },
    .build_options = .{
        .optimize = .release_safe,
        .strip = true,
    },
}
```

### Supported Primitives
- Boolean literals: `true`, `false`
- Number literals: `42`, `-3.14`, `0xFF`, `nan`, `inf`, `-inf`
- Character literals: `'a'`, `'\n'`, `'\u{1F600}'`
- Enum literals: `.foo`, `.bar`
- `null` literal
- String literals: `"hello"`, multiline strings

### Supported Containers
- Anonymous struct literals: `.{ .x = 1, .y = 2 }`
- Anonymous tuple literals: `.{ 1, 2, 3 }`

**Note:** ZON may not contain type names. Use `@import` for compile-time ZON parsing.

## Parsing ZON

**0.17: `std.zon.parse` was reworked.** Every `from*` function takes one options struct
(`gpa`, `arena`, `source`, `diagnostics`, `ignore_unknown_fields`). The result and the
diagnostics are allocated from `arena`; `gpa` is only scratch space. There is no `free` and no
`Diagnostics.deinit`: free the arena. Names moved one step:

| 0.16 | 0.17 |
|---|---|
| `fromSliceAlloc(T, gpa, src, &diag, .{})` | `fromSlice(T, .{ .gpa = gpa, .arena = arena, .source = src, .diagnostics = &diag })` |
| `fromSlice(T, gpa, src, &diag, .{})` (no pointers in `T`) | `fromSliceNoAlloc(T, .{ ... })` |
| `std.zon.parse.free(gpa, value)` | deinit the arena |
| `diag.iterateErrors()` / `getLocation` / `fmtMessage` | `diag.errors` (each has `.msg`, `.loc`), `diag.log(path)`, `diag.fatal(path)`, `"{f}", .{diag.fmt(path)}` |
| `.free_on_error` option | gone (the arena owns everything) |

`fromSliceNoAlloc` asserts at compile time that `T` has no pointers, so its result may
outlive the arena. New: `updateFromSlice(T, &value, options)` overwrites only the fields the
ZON source names — layered config files (global, then per-project) in one call each.

### Parse into Struct (Runtime)

```zig
const std = @import("std");

const Config = struct {
    name: []const u8,
    port: u16 = 8080,
    debug: bool = false,
};

const zon_str: [:0]const u8 =
    \\.{
    \\    .name = "server",
    \\    .port = 3000,
    \\}
;

pub fn main(init: std.process.Init) !void {
    var arena_state: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena_state.deinit(); // frees the result and the diagnostics
    var diag: std.zon.parse.Diagnostics = undefined;

    const config = std.zon.parse.fromSlice(Config, .{
        .gpa = init.gpa,
        .arena = arena_state.allocator(),
        .source = zon_str,
        .diagnostics = &diag,
    }) catch |err| switch (err) {
        error.ParseZon => diag.fatal("config.zon"), // logs "config.zon:L:C: msg" and exits 1
        error.OutOfMemory => |e| return e,
    };

    std.debug.print("{s}:{d} debug={}\n", .{ config.name, config.port, config.debug });
}
```

### Reporting Errors Without Exiting

```zig
const result = std.zon.parse.fromSlice(Config, .{
    .gpa = gpa,
    .arena = arena,
    .source = zon_str,
    .diagnostics = &diag,
}) catch |err| switch (err) {
    error.ParseZon => {
        diag.log("config.zon"); // std.log.err, every error with path:line:column
        for (diag.errors) |e| std.debug.print("{d}:{d}: {s}\n", .{ e.loc.line + 1, e.loc.column + 1, e.msg });
        return err;
    },
    error.OutOfMemory => |e| return e,
};
```

### Parse Options

```zig
const result = try std.zon.parse.fromSlice(T, .{
    .gpa = gpa,
    .arena = arena,
    .source = zon_str,
    .diagnostics = &diag,
    .ignore_unknown_fields = true, // default false: an unknown field is an error
});
```

### Layered Configuration: `updateFromSlice`

```zig
var config: Config = .{ .name = "default" };   // fully initialized first
try std.zon.parse.updateFromSlice(Config, &config, .{
    .gpa = gpa, .arena = arena, .source = global_zon, .diagnostics = &diag,
});
try std.zon.parse.updateFromSlice(Config, &config, .{
    .gpa = gpa, .arena = arena, .source = project_zon, .diagnostics = &diag,
});
// Fields absent from both files keep their defaults. On error `config` is valid but may be
// partially updated.
```

### Compile-Time Parsing with @import

```zig
// build.zig.zon is automatically imported at comptime
const build_zon = @import("build.zig.zon");

// Access fields directly
const name = build_zon.name;
const version = build_zon.version;
```

## Serializing to ZON

### Simple Serialization

```zig
const std = @import("std");

const Config = struct {
    name: []const u8,
    port: u16,
    enabled: bool,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    const config = Config{
        .name = "server",
        .port = 8080,
        .enabled = true,
    };

    // Serialize to allocated buffer
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try std.zon.stringify.serialize(config, .{}, &aw.writer);
    const zon_str = aw.written();
    std.debug.print("{s}\n", .{zon_str});
    // .{
    //     .name = "server",
    //     .port = 8080,
    //     .enabled = true,
    // }
}
```

### Serialize Options

```zig
try std.zon.stringify.serialize(value, .{
    // Include whitespace for readability (default: true)
    .whitespace = true,   // false for minified output

    // Emit codepoints as character literals (default: .never)
    .emit_codepoint_literals = .never,       // always emit as integers
    // .emit_codepoint_literals = .printable_ascii,  // 'a' for printable ASCII
    // .emit_codepoint_literals = .always,   // '⚡' for all valid codepoints

    // Emit []u8 as tuple instead of string (default: false)
    .emit_strings_as_containers = false,

    // Skip fields equal to their default value (default: true)
    .emit_default_optional_fields = true,  // false to omit defaults

    // 0.17: escape non-ASCII characters as \u{...} (default: false, UTF-8 passes through)
    .escape_non_ascii = false,
}, &writer);
```

### Serialization with Depth Limits (Recursive Types)

```zig
// For potentially recursive types, use depth-limited versions:

// Returns error.ExceededMaxDepth if depth exceeded
try std.zon.stringify.serializeMaxDepth(value, .{}, &writer, 16);

// No depth checking - caller must ensure no cycles
try std.zon.stringify.serializeArbitraryDepth(value, .{}, &writer);
```

## Low-Level Serializer API

Use `std.zon.Serializer` for fine-grained control over output.

### Manual Struct Serialization

```zig
var aw: std.Io.Writer.Allocating = .init(allocator);
defer aw.deinit();

var s: std.zon.Serializer = .{ .writer = &aw.writer };

var container = try s.beginStruct(.{});
try container.field("x", 10, .{});
try container.field("y", 20, .{});
try container.field("name", "point", .{});
try container.end();

// Output: .{
//     .x = 10,
//     .y = 20,
//     .name = "point",
// }
```

### Manual Tuple Serialization

```zig
var s: std.zon.Serializer = .{ .writer = &aw.writer };

var tuple = try s.beginTuple(.{});
try tuple.field(1, .{});
try tuple.field(2, .{});
try tuple.field(3, .{});
try tuple.end();

// Output: .{
//     1,
//     2,
//     3,
// }
```

### Container Options

```zig
// Control wrapping behavior
var container = try s.beginStruct(.{
    .whitespace_style = .{ .wrap = true },   // Always wrap fields
    // .whitespace_style = .{ .wrap = false }, // Never wrap (single line)
    // .whitespace_style = .{ .fields = 2 },   // Auto-wrap if > 2 fields
});
```

### Nested Containers

```zig
var s: std.zon.Serializer = .{ .writer = &aw.writer };

var root = try s.beginStruct(.{});

// Nested tuple
var coords = try root.beginTupleField("coords", .{});
try coords.field(10, .{});
try coords.field(20, .{});
try coords.end();

// Nested struct
var meta = try root.beginStructField("meta", .{});
try meta.field("id", 42, .{});
try meta.end();

try root.end();

// Output: .{
//     .coords = .{
//         10,
//         20,
//     },
//     .meta = .{
//         .id = 42,
//     },
// }
```

### Primitive Serialization

```zig
var s: std.zon.Serializer = .{ .writer = &aw.writer };

// Integer
try s.int(42);

// Float
try s.float(3.14);

// String (0.17: takes options)
try s.string("hello\nworld", .{});  // "hello\nworld"

// Multiline string
try s.multilineString("line1\nline2", .{});
// \\line1
// \\line2

// Identifier/enum literal
try s.ident("foo");  // .foo
try s.ident("var");  // .@"var" (escaped keyword)

// Unicode codepoint (0.17: takes options; non-ASCII passes through unless escaped)
try s.codePoint('a', .{});                            // 'a'
try s.codePoint('⚡', .{});                           // '⚡'
try s.codePoint('⚡', .{ .escape_non_ascii = true }); // '\u{26a1}'
```

### Value Serialization with Options

```zig
var s: std.zon.Serializer = .{ .writer = &aw.writer };

try s.value(my_value, .{
    .emit_codepoint_literals = .always,
    .emit_strings_as_containers = false,
    .emit_default_optional_fields = true,
});
```

## Supported Types

### Parse-able Types

| Zig Type | ZON Syntax |
|----------|------------|
| `bool` | `true`, `false` |
| `i32`, `u64`, etc. | `42`, `-5`, `0xFF` |
| `f32`, `f64` | `3.14`, `-0.0`, `nan`, `inf` |
| `?T` | value or `null` |
| `[]const u8` | `"string"`, multiline strings |
| `[]T` | `.{ item1, item2, ... }` |
| `[N]T` | `.{ item1, item2, ... }` (exact length) |
| `struct` | `.{ .field = value, ... }` |
| `struct (tuple)` | `.{ value1, value2, ... }` |
| `union(enum)` | `.tag` or `.{ .tag = value }` |
| `enum` | `.variant` |
| `*T` | value (auto-allocated) |
| `@Vector(N, T)` | `.{ elem1, elem2, ... }` |

### Non-serializable Types

These types cannot be serialized:
- `type`, `void` (except as union payload), `noreturn`
- Error sets/error unions
- Untagged unions
- Non-exhaustive enums
- Many-pointers (`[*]T`) or C-pointers (`[*c]T`)
- Opaque types (`anyopaque`)
- Async frame types (`anyframe`)
- Functions

## Common Patterns

### Build Configuration File

```zig
// build.zig.zon
.{
    .name = .my_project,               // enum literal
    .version = "0.1.0",
    .fingerprint = 0x0123456789abcdef, // zig build prints the value to use
    .dependencies = .{
        .zap = .{
            .url = "https://example.com/zap-0.1.0.tar.gz",
            .hash = "<name>-<version>-<hash printed by zig fetch>",
        },
    },
    .paths = .{ "src", "build.zig", "build.zig.zon" },
}
```

```zig
// build.zig - reading build.zig.zon at comptime
const build_zon = @import("build.zig.zon");
const project_name = build_zon.name;
```

### Config File with Defaults

```zig
const Config = struct {
    host: []const u8 = "localhost",
    port: u16 = 8080,
    workers: u8 = 4,
    debug: bool = false,
};

/// The returned strings live in `arena`.
fn loadConfig(io: std.Io, gpa: std.mem.Allocator, arena: std.mem.Allocator, path: []const u8) !Config {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return Config{},
        else => return err,
    };
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &buf);
    const content = try file_reader.interface.allocRemainingAlignedSentinel(
        gpa,
        .limited(1024 * 1024),
        .of(u8),
        0,  // null terminator
    );
    defer gpa.free(content);

    var diag: std.zon.parse.Diagnostics = undefined;
    return std.zon.parse.fromSlice(Config, .{
        .gpa = gpa,
        .arena = arena,
        .source = content,
        .diagnostics = &diag,
        .ignore_unknown_fields = true,
    }) catch |err| {
        if (err == error.ParseZon) diag.log(path);
        return err;
    };
}
```

### Serialize to File

```zig
fn saveConfig(io: std.Io, allocator: std.mem.Allocator, config: Config, path: []const u8) !void {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try std.zon.stringify.serialize(config, .{ .whitespace = true }, &aw.writer);

    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);

    try file.writeStreamingAll(io, aw.written());
}
```

### Union Serialization

```zig
const Value = union(enum) {
    int: i64,
    float: f64,
    string: []const u8,
    none,  // void payload
};

const v1 = Value{ .int = 42 };
// Serializes as: .{ .int = 42 }

const v2 = Value.none;
// Serializes as: .none
```

### Skip Default Fields

```zig
const Settings = struct {
    theme: []const u8 = "dark",
    font_size: u8 = 12,
    custom_value: u32,
};

const settings = Settings{ .custom_value = 100 };

try std.zon.stringify.serialize(settings, .{
    .emit_default_optional_fields = false,
}, &writer);

// Output: .{ .custom_value = 100 }
// (theme and font_size omitted because they equal defaults)
```

### Round-Trip ZON Data

```zig
/// The result lives in `arena`.
fn roundTrip(comptime T: type, allocator: std.mem.Allocator, arena: std.mem.Allocator, value: T) !T {
    // Serialize
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    try std.zon.stringify.serialize(value, .{}, &aw.writer);

    // Add null terminator for parsing
    try aw.writer.writeByte(0);
    const zon_str = aw.written();
    const terminated: [:0]const u8 = zon_str[0 .. zon_str.len - 1 :0];

    // Parse back
    var diag: std.zon.parse.Diagnostics = undefined;
    return std.zon.parse.fromSlice(T, .{
        .gpa = allocator,
        .arena = arena,
        .source = terminated,
        .diagnostics = &diag,
    });
}
```
