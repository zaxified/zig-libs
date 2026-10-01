// SPDX-License-Identifier: MIT

//! The `std.Io.VTable` every simulated host shares. It starts as a copy of
//! `std.Io.failing` — so an operation simio does not simulate yet returns the
//! error `failing` returns (never a fabricated success) — and overrides what
//! is simulated. `Io.userdata` is the `*Host` that issued the call.

const std = @import("std");
const sched = @import("sched.zig");

const Io = std.Io;
const net = Io.net;
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
    vt.operate = operate;
    vt.batchAwaitAsync = batchAwaitAsync;
    vt.batchAwaitConcurrent = batchAwaitConcurrent;
    vt.batchCancel = batchCancel;
    vt.netListenIp = netListenIp;
    vt.netAccept = netAccept;
    vt.netBindIp = netBindIp;
    vt.netConnectIp = netConnectIp;
    vt.netSend = netSend;
    vt.netRead = netRead;
    vt.netWrite = netWrite;
    vt.netClose = netClose;
    vt.netShutdown = netShutdown;
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

// ── operations and batches ────────────────────────────────────────────────

fn operate(userdata: ?*anyopaque, operation: Io.Operation) Io.Cancelable!Io.Operation.Result {
    const h = hostOf(userdata);
    return switch (operation) {
        .net_receive => |op| .{ .net_receive = try h.sim.net.receive(h, op) },
        // Files arrive with the simulated file system (M4).
        else => Io.failing.vtable.operate(null, operation),
    };
}

/// Completes `operation` now if it would not block; null otherwise.
fn tryOperate(h: *Host, operation: Io.Operation) ?Io.Operation.Result {
    return switch (operation) {
        .net_receive => |op| if (h.sim.net.tryReceive(h, op)) |r| .{ .net_receive = r } else null,
        else => Io.failing.vtable.operate(null, operation) catch unreachable, // `failing` never cancels
    };
}

/// Moves every submitted operation that can complete now to `completed`.
/// Operations that would block stay submitted, so `Batch.cancel` (which
/// aborts submissions) needs nothing from the implementation.
fn completeReady(h: *Host, batch: *Io.Batch) bool {
    var progressed = false;
    var prev: Io.Operation.OptionalIndex = .none;
    var idx = batch.submitted.head;
    while (idx != .none) {
        const i = idx.toIndex();
        const sub = batch.storage[i].submission;
        const next = sub.node.next;
        if (tryOperate(h, sub.operation)) |result| {
            switch (prev) {
                .none => batch.submitted.head = next,
                else => |p| batch.storage[p.toIndex()].submission.node.next = next,
            }
            if (batch.submitted.tail == idx) batch.submitted.tail = prev;
            batch.storage[i] = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
            switch (batch.completed.tail) {
                .none => batch.completed.head = idx,
                else => |t| batch.storage[t.toIndex()].completion.node.next = idx,
            }
            batch.completed.tail = idx;
            progressed = true;
        } else prev = idx;
        idx = next;
    }
    return progressed;
}

fn batchWait(h: *Host, batch: *Io.Batch, timeout: Io.Timeout) Io.Batch.AwaitConcurrentError!void {
    const sim = h.sim;
    const me = sim.running();
    try sim.cancelPoint(me);
    const deadline = sim.deadlineOf(h, timeout);
    while (true) {
        if (completeReady(h, batch)) return;
        if (batch.submitted.head == .none) return;
        const reason = sim.net.waitBatch(h, me, batch, deadline) catch return error.ConcurrencyUnavailable;
        switch (reason) {
            .canceled => {
                me.acknowledgeCancel();
                return error.Canceled;
            },
            .timeout => return if (completeReady(h, batch)) {} else error.Timeout,
            .normal => {},
        }
    }
}

fn batchAwaitAsync(userdata: ?*anyopaque, batch: *Io.Batch) Io.Cancelable!void {
    return batchWait(hostOf(userdata), batch, .none) catch |err| switch (err) {
        error.Canceled => error.Canceled,
        error.Timeout, error.ConcurrencyUnavailable => {}, // no deadline; out of memory acts as a spurious wakeup
    };
}

fn batchAwaitConcurrent(userdata: ?*anyopaque, batch: *Io.Batch, timeout: Io.Timeout) Io.Batch.AwaitConcurrentError!void {
    return batchWait(hostOf(userdata), batch, timeout);
}

fn batchCancel(userdata: ?*anyopaque, batch: *Io.Batch) void {
    _ = userdata;
    _ = batch; // nothing is ever left pending: see `completeReady`
}

// ── network ───────────────────────────────────────────────────────────────

fn netListenIp(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ListenOptions) net.IpAddress.ListenError!net.Socket {
    const h = hostOf(userdata);
    return h.sim.net.listen(h, address, options);
}

fn netAccept(userdata: ?*anyopaque, server: net.Socket.Handle, options: net.Server.AcceptOptions) net.Server.AcceptError!net.Socket {
    _ = options;
    const h = hostOf(userdata);
    return h.sim.net.accept(h, server);
}

fn netBindIp(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.BindOptions) net.IpAddress.BindError!net.Socket {
    const h = hostOf(userdata);
    return h.sim.net.bind(h, address, options);
}

fn netConnectIp(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ConnectOptions) net.IpAddress.ConnectError!net.Socket {
    const h = hostOf(userdata);
    return h.sim.net.connect(h, address, options);
}

fn netSend(userdata: ?*anyopaque, handle: net.Socket.Handle, messages: []net.OutgoingMessage, flags: net.SendFlags) struct { ?net.Socket.SendError, usize } {
    _ = flags;
    const h = hostOf(userdata);
    const err, const n = h.sim.net.send(h, handle, messages);
    return .{ err, n };
}

fn netRead(userdata: ?*anyopaque, src: net.Socket.Handle, data: [][]u8) net.Stream.Reader.Error!usize {
    const h = hostOf(userdata);
    return h.sim.net.read(h, src, data);
}

fn netWrite(userdata: ?*anyopaque, dest: net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) net.Stream.Writer.Error!usize {
    const h = hostOf(userdata);
    return h.sim.net.write(h, dest, header, data, splat);
}

fn netClose(userdata: ?*anyopaque, handles: []const net.Socket.Handle) void {
    const h = hostOf(userdata);
    h.sim.net.close(h, handles);
}

fn netShutdown(userdata: ?*anyopaque, handle: net.Socket.Handle, how: net.ShutdownHow) net.ShutdownError!void {
    const h = hostOf(userdata);
    return h.sim.net.shutdown(h, handle, how);
}
