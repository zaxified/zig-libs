// SPDX-License-Identifier: MIT

//! The `std.Io.VTable` every simulated host shares. It starts as a copy of
//! `std.Io.failing` — so an operation simio does not simulate yet returns the
//! error `failing` returns (never a fabricated success) — and overrides what
//! is simulated. `Io.userdata` is the `*Host` that issued the call.

const std = @import("std");
const sched = @import("sched.zig");

const Io = std.Io;
const Alignment = std.mem.Alignment;
const Host = sched.Host;
const Sim = sched.Sim;

pub const vtable: Io.VTable = blk: {
    var vt = Io.failing.vtable.*;
    vt.crashHandler = crashHandler;
    vt.async = async;
    vt.concurrent = concurrent;
    vt.await = await;
    vt.cancel = cancel;
    vt.groupAsync = groupAsync;
    vt.groupConcurrent = groupConcurrent;
    vt.groupAwait = groupAwait;
    vt.groupCancel = groupCancel;
    vt.recancel = recancel;
    vt.swapCancelProtection = swapCancelProtection;
    vt.checkCancel = checkCancel;
    vt.futexWait = futexWait;
    vt.futexWaitUncancelable = futexWaitUncancelable;
    vt.futexWake = futexWake;
    vt.now = now;
    vt.clockResolution = clockResolution;
    vt.sleep = sleep;
    vt.random = random;
    vt.randomSecure = randomSecure;
    break :blk vt;
};

fn hostOf(userdata: ?*anyopaque) *Host {
    return @ptrCast(@alignCast(userdata.?));
}

fn simOf(userdata: ?*anyopaque) *Sim {
    return hostOf(userdata).sim;
}

fn crashHandler(userdata: ?*anyopaque) void {
    _ = userdata;
}

fn async(
    userdata: ?*anyopaque,
    result: []u8,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) ?*Io.AnyFuture {
    const h = hostOf(userdata);
    return h.sim.concurrent(h, result.len, result_alignment, context, context_alignment, start) catch {
        // No unit of concurrency: run it now into the eager result.
        start(context.ptr, result.ptr);
        return null;
    };
}

fn concurrent(
    userdata: ?*anyopaque,
    result_len: usize,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) Io.ConcurrentError!*Io.AnyFuture {
    const h = hostOf(userdata);
    return h.sim.concurrent(h, result_len, result_alignment, context, context_alignment, start);
}

fn await(userdata: ?*anyopaque, any_future: *Io.AnyFuture, result: []u8, result_alignment: Alignment) void {
    simOf(userdata).await(any_future, result, result_alignment);
}

fn cancel(userdata: ?*anyopaque, any_future: *Io.AnyFuture, result: []u8, result_alignment: Alignment) void {
    simOf(userdata).cancel(any_future, result, result_alignment);
}

fn groupAsync(
    userdata: ?*anyopaque,
    group: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) void,
) void {
    const h = hostOf(userdata);
    h.sim.groupAsync(h, group, context, context_alignment, start);
}

fn groupConcurrent(
    userdata: ?*anyopaque,
    group: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) void,
) Io.ConcurrentError!void {
    const h = hostOf(userdata);
    return h.sim.groupConcurrent(h, group, context, context_alignment, start);
}

fn groupAwait(userdata: ?*anyopaque, group: *Io.Group, token: *anyopaque) Io.Cancelable!void {
    return simOf(userdata).groupAwait(group, token);
}

fn groupCancel(userdata: ?*anyopaque, group: *Io.Group, token: *anyopaque) void {
    simOf(userdata).groupCancel(group, token);
}

fn recancel(userdata: ?*anyopaque) void {
    simOf(userdata).recancel();
}

fn swapCancelProtection(userdata: ?*anyopaque, new: Io.CancelProtection) Io.CancelProtection {
    return simOf(userdata).swapCancelProtection(new);
}

fn checkCancel(userdata: ?*anyopaque) Io.Cancelable!void {
    return simOf(userdata).checkCancel();
}

fn futexWait(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: Io.Timeout) Io.Cancelable!void {
    return simOf(userdata).futexWait(ptr, expected, timeout, true);
}

fn futexWaitUncancelable(userdata: ?*anyopaque, ptr: *const u32, expected: u32) void {
    simOf(userdata).futexWait(ptr, expected, .none, false) catch unreachable; // not cancelable
}

fn futexWake(userdata: ?*anyopaque, ptr: *const u32, max_waiters: u32) void {
    simOf(userdata).futexWake(ptr, max_waiters);
}

fn now(userdata: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
    const h = hostOf(userdata);
    if (h.sim.current) |me| h.sim.maybeYield(me);
    return .{ .nanoseconds = h.clockNs(clock) };
}

fn clockResolution(userdata: ?*anyopaque, clock: Io.Clock) Io.Clock.ResolutionError!Io.Duration {
    _ = userdata;
    _ = clock;
    return .fromNanoseconds(1);
}

fn sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Cancelable!void {
    return simOf(userdata).sleep(timeout);
}

fn random(userdata: ?*anyopaque, buffer: []u8) void {
    const h = hostOf(userdata);
    h.sim.random(h, buffer);
}

/// Seeded like `random`: a simulated host has no secrets worth protecting,
/// and a draw that changed between runs would break replay.
fn randomSecure(userdata: ?*anyopaque, buffer: []u8) Io.RandomSecureError!void {
    const h = hostOf(userdata);
    h.sim.random(h, buffer);
}
