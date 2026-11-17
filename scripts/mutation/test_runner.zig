// SPDX-License-Identifier: MIT

//! The mutation kit's test runner (`zig test --test-runner
//! scripts/mutation/test_runner.zig ...`): Zig 0.17.1's default terminal
//! runner (lib/compiler/test_runner.zig, `mainTerminal`, `log`, `fuzz`
//! without fuzz mode) plus two things a schemata run needs and the default
//! runner does not have:
//!
//!   MUT_TESTS=a,b,c   run only the tests whose fully qualified name
//!                     (`zkproofs.test.foo`) contains one of the
//!                     comma-separated substrings; unset or empty = all.
//!                     Lets ONE schemata binary run each mutant against the
//!                     tests of its own file (and its callers) instead of the
//!                     whole suite -- the default runner filters only at
//!                     compile time.
//!   MUT_FAIL_FAST=0   keep going after a failed test; by default the run
//!                     stops at the first one (a killed mutant needs one).
//!
//! Output keeps the default runner's words (`FAIL (<err>)`, `<k> failed.`,
//! `All N tests passed.`), which `run.sh` classifies. No `--listen`: run the
//! binary directly, never from `zig build test`. Not for fuzz mode.

const builtin = @import("builtin");
const std = @import("std");
const testing = std.testing;

pub const std_options: std.Options = .{ .logFn = log };

var log_err_count: usize = 0;
var fba_buffer: [8192]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = .init(&fba_buffer);

pub fn main(init: std.process.Init.Minimal) void {
    const args = init.args.toSlice(fba.allocator()) catch @panic("unable to parse command line args");
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            testing.random_seed = std.fmt.parseUnsigned(u32, arg["--seed=".len..], 0) catch
                @panic("unable to parse --seed");
        } else if (std.mem.startsWith(u8, arg, "--cache-dir")) {
            // accepted and ignored, as the default runner does outside fuzz mode
        } else {
            std.debug.panic("mutation test runner: unrecognized argument {s} (no --listen: run the binary directly)", .{arg});
        }
    }
    const filter = init.environ.getPosix("MUT_TESTS") orelse "";
    const fail_fast = !std.mem.eql(u8, init.environ.getPosix("MUT_FAIL_FAST") orelse "1", "0");

    const list = builtin.test_functions;
    var ok: usize = 0;
    var skip: usize = 0;
    var fail: usize = 0;
    var ran: usize = 0;
    var leaks: usize = 0;
    for (list, 0..) |t, i| {
        if (!selected(filter, t.name)) continue;
        ran += 1;
        testing.allocator_instance = .init(std.heap.page_allocator, .{
            .canary = 0xc3a701ba,
            .check_write_after_free = true,
        });
        testing.io_instance = .init(testing.allocator, .{
            .argv0 = .init(init.args),
            .environ = init.environ,
        });
        testing.log_level = .warn;
        testing.environ = init.environ;
        std.debug.print("{d}/{d} {s}...", .{ i + 1, list.len, t.name });
        const result = t.func();
        testing.io_instance.deinit();
        const leaked = testing.allocator_instance.deinit() != 0;
        if (leaked) leaks += 1;
        if (result) |_| {
            ok += 1;
            std.debug.print("OK\n", .{});
        } else |err| switch (err) {
            error.SkipZigTest => {
                skip += 1;
                std.debug.print("SKIP\n", .{});
            },
            else => {
                fail += 1;
                std.debug.print("FAIL ({t})\n", .{err});
                if (@errorReturnTrace()) |trace| std.debug.dumpErrorReturnTrace(trace);
            },
        }
        if (fail_fast and (fail != 0 or leaked or log_err_count != 0)) break;
    }
    if (ran == 0) {
        std.debug.print("mutation test runner: MUT_TESTS={s} selects no test\n", .{filter});
        std.process.exit(2);
    }
    if (ok == ran) {
        std.debug.print("All {d} tests passed.\n", .{ok});
    } else {
        std.debug.print("{d} passed; {d} skipped; {d} failed.\n", .{ ok, skip, fail });
    }
    if (log_err_count != 0) std.debug.print("{d} errors were logged.\n", .{log_err_count});
    if (leaks != 0) std.debug.print("{d} tests leaked memory.\n", .{leaks});
    if (leaks != 0 or log_err_count != 0 or fail != 0) std.process.exit(1);
}

fn selected(filter: []const u8, name: []const u8) bool {
    if (filter.len == 0) return true;
    var it = std.mem.tokenizeScalar(u8, filter, ',');
    while (it.next()) |want| if (std.mem.find(u8, name, want) != null) return true;
    return false;
}

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@backingInt(level) <= @backingInt(std.log.Level.err)) log_err_count +|= 1;
    if (@backingInt(level) <= @backingInt(testing.log_level)) {
        std.debug.print("[" ++ @tagName(scope) ++ "] (" ++ @tagName(level) ++ "): " ++ format ++ "\n", args);
    }
}

/// `std.testing.fuzz` outside fuzz mode: the corpus, then an empty input.
pub fn fuzz(
    context: anytype,
    comptime testOne: fn (context: @TypeOf(context), *std.testing.Smith) anyerror!void,
    options: testing.FuzzInputOptions,
) anyerror!void {
    if (builtin.fuzz) @panic("the mutation test runner has no fuzz mode");
    for (options.corpus) |input| {
        var smith: testing.Smith = .{ .in = input };
        try testOne(context, &smith);
    }
    var smith: testing.Smith = .{ .in = "" };
    try testOne(context, &smith);
}
