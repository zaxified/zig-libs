// SPDX-License-Identifier: MIT

//! What a caller protecting a flaky upstream does with `resilience`: wrap a
//! fallible operation in a circuit breaker + retry-with-backoff policy via
//! `run`, watch the breaker trip after consecutive failures, then recover
//! once the upstream comes back.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const resilience = @import("resilience");

/// A pretend upstream call: fails while `remaining_failures > 0`, then
/// succeeds. Shape required by `resilience.run`: a `call()` method returning
/// an error union.
const FlakyUpstream = struct {
    remaining_failures: u32,
    attempts: u32 = 0,

    const Error = error{UpstreamDown};

    pub fn call(self: *FlakyUpstream) Error!u32 {
        self.attempts += 1;
        if (self.remaining_failures > 0) {
            self.remaining_failures -= 1;
            return error.UpstreamDown;
        }
        return 200; // pretend HTTP status
    }
};

pub fn main() !void {
    // No allocation anywhere in this module: no allocator to pass, nothing
    // to deinit.
    var breaker: resilience.CircuitBreaker = .init(.{
        .failure_threshold = 3,
        .cooldown_ms = 30_000,
    });

    // First call: three consecutive failures trip the breaker before the
    // upstream would have had a chance to recover on its own.
    var doomed: FlakyUpstream = .{ .remaining_failures = 10 };
    const result = resilience.run(&doomed, .{
        .breaker = &breaker,
        .retry = .{ .max_attempts = 3, .base_delay_ms = 1, .jitter = .none },
        .delay = .none, // don't actually sleep in an example
    });
    if (result) |status| {
        std.debug.print("upstream call unexpectedly succeeded, status={d}\n", .{status});
    } else |err| switch (err) {
        // The operation's own error, named from outside the module.
        error.UpstreamDown => std.debug.print(
            "upstream call failed after {d} attempt(s)\n",
            .{doomed.attempts},
        ),
        // The retry policy exhausted its attempts and gave up on the last
        // failure — same underlying error, but this branch is reachable too.
        else => return err,
    }
    std.debug.print("breaker state after failures: {s}\n", .{@tagName(breaker.state())});

    // A call attempted while the breaker is open fast-fails without ever
    // invoking the operation — `error.CircuitOpen` is resilience's own
    // error, distinct from the operation's error set.
    var untouched: FlakyUpstream = .{ .remaining_failures = 0 };
    const denied = resilience.run(&untouched, .{ .breaker = &breaker, .delay = .none });
    if (denied) |status| {
        std.debug.print("call unexpectedly succeeded, status={d}\n", .{status});
    } else |err| switch (err) {
        error.CircuitOpen => std.debug.print("fast-failed: breaker is open, operation not called\n", .{}),
        else => return err,
    }
    std.debug.assert(untouched.attempts == 0);

    // A bulkhead bounds concurrent in-flight calls independently of the
    // breaker — acquire, use, release.
    var bulkhead: resilience.Bulkhead = .init(.{ .max_concurrent = 1 });
    try bulkhead.acquire();
    std.debug.print("bulkhead slots in use: {d}/1\n", .{bulkhead.activeCount()});
    // A second acquire at capacity fails fast rather than blocking.
    bulkhead.acquire() catch |err| switch (err) {
        error.BulkheadFull => std.debug.print("bulkhead full, shedding load\n", .{}),
    };
    bulkhead.release();
    std.debug.print("bulkhead slots in use: {d}/1\n", .{bulkhead.activeCount()});
}
