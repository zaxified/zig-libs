// SPDX-License-Identifier: MIT

//! `testkit` example — how a module's tests actually use this harness.
//!
//! testkit is test-only: `build.zig` wires it into each consumer's TEST
//! binary via `test_deps`, never into the module a downstream user imports
//! (see root.zig's doc comment). Its consumer is not an application, it is
//! whoever is writing a `goldens.zig` or a module test file — this program
//! is what they read.
//!
//! Allocation: `hex.alloc` is the only allocating entry point in the whole
//! module, exercised below under a leak-checking allocator. Everything else
//! here is allocation-free.

const std = @import("std");
const testkit = @import("testkit");

/// A gate, not a printout: every check below goes through this rather than
/// `std.debug.assert`, which `ReleaseFast` compiles out entirely -- an
/// example meant to fail loudly must not rely on a mechanism that can
/// silently stop checking anything.
fn check(cond: bool, comptime what: []const u8) !void {
    if (!cond) {
        std.debug.print("FAILED: {s}\n", .{what});
        return error.ExampleCheckFailed;
    }
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // ── hex: the three shapes a KAT vector gets decoded in ──────────────

    // Comptime, for a container-scope constant vector.
    const kat = comptime testkit.hex.bytes(4, "deadbeef");
    try check(std.mem.eql(u8, &kat, &.{ 0xde, 0xad, 0xbe, 0xef }), "hex.bytes (comptime)");

    // Runtime, into a caller-owned buffer.
    var buf: [4]u8 = undefined;
    const decoded = try testkit.hex.into(&buf, "cafebabe");
    try check(std.mem.eql(u8, decoded, &.{ 0xca, 0xfe, 0xba, 0xbe }), "hex.into");

    // Runtime, allocated -- the only path in this module that allocates.
    const owned = try testkit.hex.alloc(alloc, "0102030405");
    defer alloc.free(owned);
    try check(std.mem.eql(u8, owned, &.{ 1, 2, 3, 4, 5 }), "hex.alloc");

    // Negative case, by NAMED error: a malformed hex literal must be
    // rejected as `error.InvalidCharacter`, not swallowed by a blanket catch.
    if (testkit.hex.alloc(alloc, "zz")) |_| {
        return error.ExpectedDecodeToFail;
    } else |err| switch (err) {
        error.InvalidCharacter => {}, // expected: 'z' is not a hex digit
        else => return err,
    }

    // ── goldens: the byte-comparison every goldens.zig wants ────────────

    // The golden stays hex at the call site (what a capture tool printed);
    // expectHex decodes it and diffs against the actual bytes.
    try testkit.expectHex("cafebabe", &.{ 0xca, 0xfe, 0xba, 0xbe });
    // expectBytes is the same comparison when you already have both sides
    // decoded -- e.g. two encoder outputs, not a hex golden.
    try testkit.expectBytes(&.{ 1, 2, 3 }, &.{ 1, 2, 3 });

    // ── skips: the env-gated decision, the pure half ────────────────────

    // verboseEnabled is the pure decision `verboseSkip` wraps around an env
    // read; drive it directly with the cases its own tests pin. `getEnv` and
    // `verboseSkip` themselves are demonstrated below instead of here --
    // see the comment on the `test` block for why `main` cannot call them.
    try check(!testkit.verboseEnabled(null), "verboseEnabled(null) is off");
    try check(!testkit.verboseEnabled(""), "verboseEnabled(\"\") is off (FOO= clears, not enables)");
    try check(testkit.verboseEnabled("1"), "verboseEnabled(\"1\") is on");

    std.debug.print("testkit example: all checks passed\n", .{});
}

// Two pieces of the public surface cannot be driven from `main` above, for
// two DIFFERENT reasons -- both demonstrated here instead, the only context
// where each has the meaning the API promises:
//
// `skip` is meant to be called as `return testkit.skip(...)` from inside a
// `test`: it always returns `error.SkipZigTest`, the one error value Zig's
// own test runner special-cases as "skipped" rather than "failed" (the doc
// comment on `skip` is explicit that this is the whole point of the design --
// a bare `return` after printing was the bug it replaced). `main` has no
// such runner watching it; calling `skip` there would just be an ordinary
// error propagating out of `main` and failing the program, indistinguishable
// from any other error -- not what the API means, and misleading to show.
//
// `getEnv` (and `verboseSkip`, which is built on it) is a harder case: it is
// not merely pointless outside a test, it does not COMPILE there. Its body
// reads `std.testing.environ`, and std's own declaration of that var is
// `if (builtin.is_test) undefined else @compileError("not testing")` --
// gated on whether the CURRENT COMPILATION is a test binary, not on whether
// the call happens to sit inside a `test { }` block. `example/main.zig` is
// built with `b.addExecutable`, so `builtin.is_test` is `false` for the
// whole file regardless of where a call to `getEnv` textually appears;
// putting it in `main` was tried first and fails with exactly that
// `@compileError`. This file only compiles both functions at all because
// this `test` declaration is never analyzed by `zig build-exe` in the first
// place (test blocks are only ever compiled by `zig build test-*`, which use
// `b.addTest` and so always have `builtin.is_test == true`) -- the same
// reason `skip` above is safe to call here.
test "skip, getEnv and verboseSkip only make sense inside a real test binary" {
    const wouldSkip = struct {
        fn call() error{SkipZigTest} {
            return testkit.skip("demo: {s}", .{"a real call site names the actual reason"});
        }
    }.call;
    // `skip`'s return type is the bare error set `error{SkipZigTest}`, not an
    // error union -- there is no non-error case to unwrap, so this is a
    // value comparison (`expectEqual`), the same way root.zig's own test for
    // `skip` checks it, not `expectError`.
    try std.testing.expectEqual(error.SkipZigTest, wouldSkip());

    const env_val = testkit.getEnv(testkit.verbose_skip_env);
    try std.testing.expectEqual(testkit.verboseEnabled(env_val), testkit.verboseSkip());
}
