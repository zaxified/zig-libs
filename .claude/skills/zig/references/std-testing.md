# std.testing

Unit testing utilities and assertions for Zig tests.

## Quick Reference

| Function | Purpose |
|----------|---------|
| `expect(bool)` | Assert condition is true |
| `expectEqual(expected, actual)` | Shallow equality (peer type resolution) |
| `expectEqualDeep(expected, actual)` | Deep equality (follows pointers, compares contents) |
| `expectEqualStrings(expected, actual)` | String equality with diff output |
| `expectEqualSlices(T, expected, actual)` | Slice equality with diff output |
| `expectError(error, result)` | Assert specific error returned |
| `expectApproxEqAbs/Rel(expected, actual, tolerance)` | Float comparison |
| `expectFmt(expected, template, args)` | Format string output |
| `expectStringStartsWith(actual, prefix)` | String prefix check |
| `expectStringEndsWith(actual, suffix)` | String suffix check |

## Basic Assertions

```zig
const testing = std.testing;

// Boolean condition
try testing.expect(value > 0);

// Equality (uses peer type resolution)
try testing.expectEqual(expected, actual);
try testing.expectEqual(@as(u32, 42), some_u32);

// String equality (with visual diff on failure)
try testing.expectEqualStrings("hello", slice);

// String prefix/suffix
try testing.expectStringStartsWith(path, "/home/");
try testing.expectStringEndsWith(filename, ".zig");

// Slice equality (with visual diff, works with any element type)
try testing.expectEqualSlices(u8, expected_bytes, actual_bytes);
try testing.expectEqualSlices(u32, &[_]u32{1, 2, 3}, result_slice);

// Sentinel-terminated slice equality
try testing.expectEqualSentinel(u8, 0, expected_cstr, actual_cstr);

// Deep equality (recursively compares structs, arrays, pointers)
try testing.expectEqualDeep(expected_struct, actual_struct);

// Float comparison (absolute tolerance)
try testing.expectApproxEqAbs(@as(f32, 1.0), result, 0.001);

// Float comparison (relative tolerance)
try testing.expectApproxEqRel(@as(f64, 100.0), result, 0.01);
```

### expectEqual vs expectEqualDeep

```zig
const Point = struct { x: i32, y: i32 };

// expectEqual - compares by value for primitives, by identity for pointers
const p1 = Point{ .x = 1, .y = 2 };
const p2 = Point{ .x = 1, .y = 2 };
try testing.expectEqual(p1, p2);  // OK - structs compared field-by-field

// For slices, expectEqual compares ptr and len (identity)
const a = [_]u8{ 1, 2, 3 };
const b = [_]u8{ 1, 2, 3 };
// testing.expectEqual(&a, &b);  // FAILS - different pointers

// expectEqualDeep - follows pointers, compares contents
try testing.expectEqualDeep(&a, &b);  // OK - compares contents
try testing.expectEqualDeep("abc", "abc");  // OK
```

## Error Assertions

```zig
// Expect specific error
try testing.expectError(error.OutOfMemory, fallible_function());

// Unwrap or fail test (using try directly)
const value = try fallible_function();  // fails test on any error
```

## Format Testing

```zig
// Test format string output
try testing.expectFmt("42", "{}", .{@as(u32, 42)});
try testing.expectFmt("hello world", "{s} {s}", .{"hello", "world"});
```

## Testing Allocator

`std.testing.allocator` is a `DebugAllocator` (formerly `GeneralPurposeAllocator`) that detects memory leaks and use-after-free. **Only available in test builds.**

```zig
test "with allocator" {
    // Detects leaks and use-after-free
    var list: std.ArrayList(u32) = .empty;
    defer list.deinit(testing.allocator);

    try list.append(testing.allocator, 42);
    try testing.expectEqual(@as(usize, 1), list.items.len);
}
// If defer is missing, test fails with leak report
```

## Failing Allocator

`std.testing.failing_allocator` always returns `error.OutOfMemory`. Use for testing error paths:

```zig
test "handle allocation failure" {
    try testing.expectError(
        error.OutOfMemory,
        testing.failing_allocator.alloc(u8, 100)
    );
}
```

### Configurable FailingAllocator

For controlled failure testing, use `FailingAllocator` to fail after N allocations:

```zig
test "fail on third allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = 2,  // First 2 allocations succeed, third fails
    });
    const allocator = failing.allocator();

    const a = try allocator.create(i32);  // succeeds (index 0)
    defer allocator.destroy(a);
    const b = try allocator.create(i32);  // succeeds (index 1)
    defer allocator.destroy(b);

    try testing.expectError(error.OutOfMemory, allocator.create(i32));  // fails (index 2)
}

// Configuration options
var failing = std.testing.FailingAllocator.init(backing_allocator, .{
    .fail_index = 5,         // Fail on 6th allocation (default: never)
    .resize_fail_index = 3,  // Fail on 4th resize (default: never)
});

// Inspect state after use
std.debug.print("Allocated: {} bytes\n", .{failing.allocated_bytes});
std.debug.print("Freed: {} bytes\n", .{failing.freed_bytes});
std.debug.print("Allocations: {}\n", .{failing.allocations});
std.debug.print("Deallocations: {}\n", .{failing.deallocations});
```

## Exhaustive Allocation Failure Testing

`checkAllAllocationFailures` tests that your code handles `OutOfMemory` at every allocation point without leaking:

```zig
fn myFunction(allocator: std.mem.Allocator, size: usize) !void {
    var foo = try allocator.alloc(u8, size);
    defer allocator.free(foo);
    var bar = try allocator.alloc(u8, size);
    defer allocator.free(bar);
    // ... use foo and bar
}

test "no leaks on allocation failure" {
    // Runs myFunction multiple times, failing each allocation in turn
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        myFunction,
        .{@as(usize, 10)},  // extra args tuple
    );
}
```

**How it works:**
1. Runs function once to count total allocations
2. Runs N more times, failing allocation 0, then 1, then 2...
3. Verifies `OutOfMemory` is returned and no memory leaked

**Errors returned:**
- `error.MemoryLeakDetected` - allocation failed but memory wasn't freed
- `error.SwallowedOutOfMemoryError` - `OutOfMemory` was caught but not propagated
- `error.NondeterministicMemoryUsage` - allocation count varies between runs

## Temporary Directory

Create an isolated temp directory for file system tests:

```zig
test "file operations" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});  // creates .zig-cache/tmp/<random>/
    defer tmp.cleanup();

    // Write and read files
    var file = try tmp.dir.createFile(io, "test.txt", .{});
    defer file.close(io);
    try file.writeStreamingAll(io, "hello");

    // Use tmp.dir for all operations
    const content = try tmp.dir.readFileAlloc(io, "test.txt", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(content);
    try testing.expectEqualStrings("hello", content);
}
```

## Test Organization

```zig
test "descriptive test name" {
    // test body
}

test {
    // Anonymous test, runs with others
}

// Reference other tests (pulls in tests from imported module)
test {
    _ = @import("other_module.zig");
}

// Force semantic analysis of all declarations (catches unused code errors)
comptime {
    std.testing.refAllDecls(@This());
}

// Recursive version for nested types
// 0.16: std.testing.refAllDeclsRecursive is gone — only the non-recursive refAllDecls remains.
// Write your own recursion if you need to reach into nested container types:
fn refAllDeclsRecursive(comptime T: type) void {
    inline for (comptime std.meta.declarations(T)) |decl| {
        if (@TypeOf(@field(T, decl.name)) == type) {
            switch (@typeInfo(@field(T, decl.name))) {
                .@"struct", .@"enum", .@"union", .@"opaque" => refAllDeclsRecursive(@field(T, decl.name)),
                else => {},
            }
        }
        _ = &@field(T, decl.name);
    }
}

comptime {
    refAllDeclsRecursive(@This());
}
```

## Skip Tests

```zig
test "skip this" {
    return error.SkipZigTest;
}

test "conditional skip" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    // ...
}

test "skip if feature unavailable" {
    if (!@hasDecl(std.os, "linux")) return error.SkipZigTest;
    // Linux-specific test...
}
```

## Test Logging

```zig
test "with logging" {
    // Only shown when test fails or with --verbose
    std.debug.print("Debug info: {}\n", .{value});
}

// Configurable log level for tests
// std.testing.log_level = .debug;  // default is .warn
```

## Deterministic Randomness

Tests have access to a deterministic random seed for reproducible "random" tests:

```zig
test "deterministic random" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const value = random.int(u32);
    // Same seed = same value on every run
}
```

## Fuzz Testing

**0.17.0-dev signature change:** `testOne` receives a `*std.testing.Smith`
value generator, **not** a `[]const u8`. Older examples (including most
training data) will not compile.

```zig
// A doc comment cannot be attached to a test -- `///` here is a compile error.
test "fuzz parser" {
    try std.testing.fuzz({}, fuzzOne, .{});   // .{ .corpus = &.{...} } to seed
}

fn fuzzOne(_: void, smith: *std.testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    const n = smith.slice(&buf);              // returns bytes written
    _ = myParser.parse(buf[0..n]) catch |err| switch (err) {
        error.InvalidInput => return,          // expected
        else => return err,
    };
}
```

`Smith` produces structured values rather than raw input: `smith.value(T)`,
`smith.valueRangeAtMost(T, lo, hi)`, `smith.slice(buf)`,
`smith.eosWeightedSimple(false_w, true_w)`, `smith.boolWeighted(...)`.

```bash
zig build test --fuzz=200000   # bounded run, prints a coverage report
zig build test --fuzz          # unbounded + web UI of covered lines
```

A plain `zig build test` runs the fuzz test once with a trivial input.
The corpus persists in `.zig-cache/f/` and compounds across runs — that
accumulation, not the length of any single run, is where coverage-guided
fuzzing pays off. See [Quality Tooling](quality-tooling.md) for the
measurements and the traps.

## Common Patterns

### Table-Driven Tests

```zig
test "parameterized" {
    const cases = [_]struct { input: i32, expected: i32 }{
        .{ .input = 0, .expected = 0 },
        .{ .input = 1, .expected = 1 },
        .{ .input = -1, .expected = 1 },
    };

    for (cases) |case| {
        try testing.expectEqual(case.expected, abs(case.input));
    }
}
```

### Test Context/Fixture

```zig
const TestContext = struct {
    allocator: std.mem.Allocator,
    data: *Data,

    fn init(ally: std.mem.Allocator) !TestContext {
        const data = try ally.create(Data);
        return .{ .allocator = ally, .data = data };
    }

    fn deinit(self: *TestContext) void {
        self.allocator.destroy(self.data);
    }
};

test "with context" {
    var ctx = try TestContext.init(testing.allocator);
    defer ctx.deinit();
    // use ctx.data...
}
```

### Testing with ArenaAllocator

```zig
test "arena for test allocations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();

    // No need for individual frees - arena handles cleanup
    const a = try ally.alloc(u8, 100);
    const b = try ally.alloc(u8, 200);
    _ = a; _ = b;
    // arena.deinit() frees everything
}
```

## Running Tests

```bash
zig build test                    # Run all tests
zig test src/lib.zig              # Test single file
zig test --test-filter "name"     # Filter by name substring
zig test -fsummary                # Show test summary
zig test --verbose                # Show debug output
```
