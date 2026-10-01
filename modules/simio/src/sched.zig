// SPDX-License-Identifier: MIT

//! The scheduler: fibers on one OS thread, a seeded ready set, virtual time and
//! the `std.Io` concurrency entries (async/concurrent/await/cancel, groups,
//! cancel protection, futex, sleep, clocks, randomness).
//!
//! Every task is a fiber. The thread that calls `Sim.run` is the scheduler
//! context: it picks the next ready fiber (seeded, or FIFO), switches to it, and
//! regains control only when that fiber blocks, yields or finishes. There is no
//! preemption, so nothing here needs an atomic; a second OS thread touching a
//! simulation is a bug and is asserted against in safe builds.
//!
//! Virtual time advances only when no fiber is ready, by jumping to the
//! earliest timer. Computation takes zero simulated time.
//!
//! Pattern reference: Zig's own `std/Io/Uring.zig` (MIT) — the fiber entry
//! trampoline and the initial context layout follow it; the scheduler, the wait
//! bookkeeping and everything single-threaded are this module's own.

const std = @import("std");
const builtin = @import("builtin");
const netsim = @import("netsim");
const stack_mod = @import("stack.zig");
const net_mod = @import("net.zig");
const fs_mod = @import("fs.zig");

const Io = std.Io;
const Alignment = std.mem.Alignment;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const fiber = Io.fiber;
const Prng = netsim.Prng;

comptime {
    if (!fiber.supported) @compileError("simio needs std.Io.fiber (x86_64, aarch64 or riscv64)");
}

pub const Options = struct {
    seed: u64,
    /// How the next task is chosen among the ready ones. `.random` draws from
    /// the seed (different seeds explore different interleavings); `.fifo`
    /// runs them in the order they became ready.
    schedule: enum { random, fifo } = .random,
    /// Probability (per mille) that a task is rescheduled at a yield point —
    /// most `Io` calls that do not block anyway. 0 means a task runs until it
    /// blocks. Ignored by `.fifo`.
    preempt_permille: u16 = 100,
    /// Virtual size of each task's stack (committed lazily; one guard page
    /// is added below it).
    stack_size: usize = 4 * 1024 * 1024,
    /// Scheduling decisions after which `run` gives up with `.step_limit`.
    max_steps: u64 = 50_000_000,
    /// Wall-clock time of simulated instant 0, nanoseconds since the Unix
    /// epoch. Default: 2026-01-01T00:00:00Z.
    epoch_ns: i96 = 1_767_225_600 * std.time.ns_per_s,
    /// The simulated network's behaviour (streams, timeouts, short reads).
    net: net_mod.NetOptions = .{},
    /// The simulated file systems' durability model.
    fs: fs_mod.FsOptions = .{},
};

pub const HostOptions = struct {
    /// Offset of this host's real-time clock from the simulation's, ns.
    clock_skew_ns: i64 = 0,
    /// IPv4 address. Default: 10.0.0.0 + host index + 1.
    ip4: ?[4]u8 = null,
    /// IPv6 address. Default: fd00:: + host index + 1.
    ip6: ?[16]u8 = null,
    /// Disk capacity; writes past it fail with `error.NoSpaceLeft`.
    disk_bytes: ?u64 = null,
};

pub const Outcome = enum {
    /// No task is ready, no timer is pending, and every task has finished.
    quiescent,
    /// No task is ready and no timer is pending, but tasks are still blocked:
    /// nothing can ever wake them.
    deadlock,
    /// `Options.max_steps` scheduling decisions were made.
    step_limit,
    /// `runFor`'s duration elapsed; call `run`/`runFor` again to continue.
    time_limit,
    /// The invariant hook (`setInvariant`) returned an error; see
    /// `RunResult.violation`.
    violated,
};

pub const RunResult = struct {
    outcome: Outcome,
    /// Scheduling decisions made so far (cumulative across `run` calls).
    steps: u64,
    /// Tasks that are blocked forever (`.deadlock` only).
    blocked: usize,
    /// Virtual time at return, ns since simulated instant 0.
    now_ns: u64,
    /// `.violated` only: what the invariant hook returned.
    violation: ?anyerror = null,
};

/// A fault applied to a running simulation, in simio's units (ns). The
/// search layer translates `netsim.FaultKind` schedules into these.
pub const Fault = union(enum) {
    link_down: struct { from: u32, to: u32 },
    link_up: struct { from: u32, to: u32 },
    partition: struct { id: u32, cut: []const u32 },
    heal: u32,
    crash: u32,
    restart: u32,
    clock_jump: struct { host: u32, delta_ns: i64 },
    drop_once: struct { from: u32, to: u32 },
    dup_once: struct { from: u32, to: u32 },
    delay_once: struct { from: u32, to: u32, extra_ns: u64 },
    /// The next read, write or sync on the host's disk fails with
    /// `error.InputOutput`.
    disk_error: struct { host: u32, op: enum { read, write, sync } },
    /// One bit of one stored file flips, silently.
    bit_rot: u32,
};

const State = enum { ready, running, blocked, done };

pub const WakeReason = enum { normal, timeout, canceled };

pub const Wait = union(enum) {
    none,
    futex: *const u32,
    sleep,
    await_future,
    group: *GroupState,
    /// Waiting for a socket's state to change.
    sock: *net_mod.Sock,
    /// Waiting for any socket of an `Io.Batch` (registered on each).
    batch,
};

const Task = union(enum) {
    future: *const fn (context: *const anyopaque, result: *anyopaque) void,
    group: *const fn (context: *const anyopaque) void,
};

pub const Fiber = struct {
    context: fiber.Context,
    sim: *Sim,
    host: *Host,
    id: u64,
    state: State,
    stack: stack_mod.Stack,
    task: Task,
    context_mem: []u8,
    context_align: Alignment,
    result_mem: []u8,
    result_align: Alignment,
    /// `.future` tasks: the task blocked in `await`/`cancel` on this one.
    awaiter: ?*Fiber = null,
    /// `.group` tasks: the group this task belongs to.
    group: ?*GroupState = null,

    cancel_requested: bool = false,
    /// The request was delivered as `error.Canceled`; `recancel` re-arms it.
    cancel_acked: bool = false,
    protection: Io.CancelProtection = .unblocked,

    wait: Wait = .none,
    cancelable: bool = false,
    wake_reason: WakeReason = .normal,
    /// Bumped on every wake, so a timer armed for an earlier wait is stale.
    wait_gen: u64 = 0,

    fn cancelPending(f: *const Fiber) bool {
        return f.cancel_requested and !f.cancel_acked and f.protection == .unblocked;
    }

    fn acknowledge(f: *Fiber) void {
        assert(f.cancelPending());
        f.cancel_acked = true;
    }

    /// Records that `error.Canceled` is being returned for the pending
    /// request (after a wait ended with `.canceled`).
    pub fn acknowledgeCancel(f: *Fiber) void {
        f.acknowledge();
    }
};

const GroupState = struct {
    members: std.ArrayList(*Fiber) = .empty,
    awaiter: ?*Fiber = null,
    /// `groupCancel` ran, or the awaiter was canceled: members added later
    /// are canceled at birth too.
    cancel_all: bool = false,
    /// The awaiter's own cancelation arrived while it was waiting.
    awaiter_canceled: bool = false,
};

const Event = struct {
    at: u64,
    seq: u64,
    kind: union(enum) {
        /// End a task's wait with `.timeout`, unless that wait already ended
        /// (or the task is gone: its host crashed). `id` guards against a
        /// new fiber reusing the address.
        wake: struct { fiber: *Fiber, id: u64, gen: u64 },
        net: net_mod.Event,
        fault: Fault,
    },

    fn order(_: void, a: Event, b: Event) std.math.Order {
        if (a.at != b.at) return std.math.order(a.at, b.at);
        return std.math.order(a.seq, b.seq);
    }
};

/// One simulated machine. Its `io()` is the `std.Io` its code runs on.
pub const Host = struct {
    sim: *Sim,
    id: u32,
    prng: Prng,
    clock_skew_ns: i64,
    ip4: [4]u8,
    ip6: [16]u8,
    /// False while the host is crashed; a down host is unreachable.
    up: bool = true,
    /// Virtual time of the last (re)boot; monotonic clocks count from here.
    boot_ns: u64 = 0,
    /// How many times the host has crashed.
    crashes: u32 = 0,
    /// Tasks started again on every restart (`spawnBoot`).
    boots: std.ArrayList(Boot) = .empty,
    /// What the host's code allocated through `allocator()` and has not
    /// freed: a crash releases it, as a power cut releases RAM.
    live_allocs: std.AutoHashMapUnmanaged(usize, Alloc) = .empty,
    /// The host's disk (see `fs.zig` for what survives a crash).
    fs: fs_mod.Fs = undefined,
    handles: std.AutoHashMapUnmanaged(Io.net.Socket.Handle, *net_mod.Sock) = .empty,
    next_handle: Io.net.Socket.Handle = 3,
    next_port: u16 = 49152,
    root_group: Io.Group = .init,
    /// The first error a root task (`spawn`) returned, if any.
    failure: ?anyerror = null,
    /// How many root tasks returned an error.
    failures: usize = 0,

    const Boot = struct {
        start: *const fn (context: *const anyopaque) void,
        context: []u8,
        context_align: Alignment,
    };

    const Alloc = struct { len: usize, alignment: Alignment };

    pub fn io(h: *Host) Io {
        return .{ .userdata = h, .vtable = &@import("vtable.zig").vtable };
    }

    /// Puts a file on the host's disk before (or between) runs, durable at
    /// once: configuration, fixtures, a pre-existing database.
    pub fn putFile(h: *Host, path: []const u8, data: []const u8) !void {
        return h.fs.put(path, data);
    }

    /// The current contents of a file on the host's disk, or null.
    pub fn readFile(h: *Host, path: []const u8) ?[]const u8 {
        return h.fs.get(path);
    }

    /// What the host's code wrote to stdout and stderr (the first 64 KiB).
    pub fn console(h: *const Host) []const u8 {
        return h.fs.console.items;
    }

    /// This host's memory. Use it for everything the host's code allocates
    /// when the host may crash: a crash frees whatever is still live, so a
    /// crash is not reported as a leak, and nothing survives it by accident.
    pub fn allocator(h: *Host) Allocator {
        return .{ .ptr = h, .vtable = &host_alloc_vtable };
    }

    const host_alloc_vtable: Allocator.VTable = .{
        .alloc = hostAlloc,
        .resize = hostResize,
        .remap = hostRemap,
        .free = hostFree,
    };

    fn hostAlloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret: usize) ?[*]u8 {
        const h: *Host = @ptrCast(@alignCast(ctx));
        const gpa = h.sim.gpa;
        h.live_allocs.ensureUnusedCapacity(gpa, 1) catch return null;
        const p = gpa.rawAlloc(len, alignment, ret) orelse return null;
        h.live_allocs.putAssumeCapacity(@intFromPtr(p), .{ .len = len, .alignment = alignment });
        return p;
    }

    fn hostResize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret: usize) bool {
        const h: *Host = @ptrCast(@alignCast(ctx));
        if (!h.sim.gpa.rawResize(memory, alignment, new_len, ret)) return false;
        h.live_allocs.getPtr(@intFromPtr(memory.ptr)).?.len = new_len;
        return true;
    }

    fn hostRemap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const h: *Host = @ptrCast(@alignCast(ctx));
        h.live_allocs.ensureUnusedCapacity(h.sim.gpa, 1) catch return null;
        const p = h.sim.gpa.rawRemap(memory, alignment, new_len, ret) orelse return null;
        _ = h.live_allocs.remove(@intFromPtr(memory.ptr));
        h.live_allocs.putAssumeCapacity(@intFromPtr(p), .{ .len = new_len, .alignment = alignment });
        return p;
    }

    fn hostFree(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret: usize) void {
        const h: *Host = @ptrCast(@alignCast(ctx));
        _ = h.live_allocs.remove(@intFromPtr(memory.ptr));
        h.sim.gpa.rawFree(memory, alignment, ret);
    }

    /// Allocations made through `allocator()` and not yet freed.
    pub fn liveAllocations(h: *const Host) usize {
        return h.live_allocs.count();
    }

    fn releaseAll(h: *Host) void {
        var it = h.live_allocs.iterator();
        while (it.next()) |e| {
            const ptr: [*]u8 = @ptrFromInt(e.key_ptr.*);
            h.sim.gpa.rawFree(ptr[0..e.value_ptr.len], e.value_ptr.alignment, @returnAddress());
        }
        h.live_allocs.clearRetainingCapacity();
    }

    /// Like `spawn`, and the task is started again every time the host
    /// restarts after a crash — the host's "main". `args` are copied and
    /// reused as they are: they must stay valid across crashes (test-owned
    /// state, or durable state that lives outside the host's memory).
    pub fn spawnBoot(
        h: *Host,
        comptime function: anytype,
        args: std.meta.ArgsTuple(@TypeOf(function)),
    ) error{OutOfMemory}!void {
        const Args = @TypeOf(args);
        const Ctx = struct { host: *Host, args: Args };
        const ctx: Ctx = .{ .host = h, .args = args };
        const gpa = h.sim.gpa;
        try h.boots.ensureUnusedCapacity(gpa, 1);
        const mem = gpa.rawAlloc(@sizeOf(Ctx), .of(Ctx), @returnAddress()) orelse return error.OutOfMemory;
        @memcpy(mem[0..@sizeOf(Ctx)], std.mem.asBytes(&ctx));
        h.boots.appendAssumeCapacity(.{
            .start = Erased(function, Args).start,
            .context = mem[0..@sizeOf(Ctx)],
            .context_align = .of(Ctx),
        });
        if (h.up) _ = try h.sim.spawnGroupTask(h, &h.root_group, mem[0..@sizeOf(Ctx)], .of(Ctx), Erased(function, Args).start);
    }

    fn Erased(comptime function: anytype, comptime Args: type) type {
        const Ctx = struct { host: *Host, args: Args };
        return struct {
            fn start(context: *const anyopaque) void {
                const c: *const Ctx = @ptrCast(@alignCast(context));
                const R = @typeInfo(@TypeOf(function)).@"fn".return_type.?;
                if (@typeInfo(R) == .error_union) {
                    _ = @call(.auto, function, c.args) catch |err| {
                        c.host.failures += 1;
                        if (c.host.failure == null) c.host.failure = err;
                    };
                } else {
                    _ = @call(.auto, function, c.args);
                }
            }
        };
    }

    /// Starts `function(args...)` as a root task of this host. An error it
    /// returns is recorded in `failure`/`failures` rather than discarded.
    pub fn spawn(
        h: *Host,
        comptime function: anytype,
        args: std.meta.ArgsTuple(@TypeOf(function)),
    ) error{OutOfMemory}!void {
        const Args = @TypeOf(args);
        const Ctx = struct { host: *Host, args: Args };
        const ctx: Ctx = .{ .host = h, .args = args };
        if (!h.up) return; // a crashed host runs nothing
        _ = try h.sim.spawnGroupTask(h, &h.root_group, std.mem.asBytes(&ctx), .of(Ctx), Erased(function, Args).start);
    }

    /// Virtual reading of `clock` on this host, ns.
    pub fn clockNs(h: *const Host, clock: Io.Clock) i96 {
        const t: i96 = h.sim.now;
        return switch (clock) {
            .real => h.sim.opts.epoch_ns + t + h.clock_skew_ns,
            // Monotonic clocks count from host boot; start at 1 s so a zero
            // reading never looks like "unset".
            .awake, .boot, .cpu_process, .cpu_thread => std.time.ns_per_s + t - h.boot_ns,
        };
    }
};

pub const Sim = struct {
    gpa: Allocator,
    opts: Options,
    prng: Prng,
    /// Virtual time, ns since simulated instant 0.
    now: u64 = 0,
    seq: u64 = 0,
    next_fiber_id: u64 = 1,
    steps: u64 = 0,
    next_partition: u32 = 1 << 31,
    fingerprint_state: u64 = 0,
    live: usize = 0,

    sched_context: fiber.Context = undefined,
    current: ?*Fiber = null,
    ready: std.ArrayList(*Fiber) = .empty,
    events: std.PriorityQueue(Event, void, Event.order) = .empty,
    net: net_mod.Net,
    futex_waiters: std.ArrayList(*Fiber) = .empty,
    hosts: std.ArrayList(*Host) = .empty,
    free_stacks: std.ArrayList(stack_mod.Stack) = .empty,
    /// Every fiber not yet destroyed, so `deinit` can release the ones a
    /// deadlock or the step limit left behind. Invariant: `ready` has
    /// capacity for all of them, so waking a task never allocates.
    fibers: std.AutoArrayHashMapUnmanaged(*Fiber, void) = .empty,
    invariant: ?struct { check: *const fn (sim: *Sim, ctx: ?*anyopaque) anyerror!void, ctx: ?*anyopaque } = null,
    owner: std.Thread.Id,

    /// Initializes in place: hosts and tasks keep pointers to the `Sim`.
    pub fn init(sim: *Sim, gpa: Allocator, opts: Options) void {
        sim.* = .{
            .gpa = gpa,
            .opts = opts,
            .prng = .init(opts.seed),
            .net = undefined,
            .owner = std.Thread.getCurrentId(),
        };
        sim.net = .init(sim, opts.seed);
    }

    pub fn deinit(sim: *Sim) void {
        assert(sim.current == null);
        // Tasks still alive (deadlocked, or cut off by the step limit) and
        // futures nobody awaited are discarded without unwinding — their
        // stacks are simply unmapped. Their groups go with them.
        const gpa = sim.gpa; // `sim` is undefined by the time the defer runs
        var groups: std.AutoArrayHashMapUnmanaged(*GroupState, void) = .empty;
        defer groups.deinit(gpa);
        for (sim.hosts.items) |h| if (h.root_group.token.raw) |token| {
            groups.put(sim.gpa, @ptrCast(@alignCast(token)), {}) catch {};
        };
        while (sim.fibers.count() > 0) {
            const f = sim.fibers.keys()[sim.fibers.count() - 1];
            if (f.group) |g| groups.put(sim.gpa, g, {}) catch {};
            sim.destroyFiber(f);
        }
        sim.fibers.deinit(sim.gpa);
        for (groups.keys()) |g| {
            g.members.deinit(sim.gpa);
            sim.gpa.destroy(g);
        }
        while (sim.events.pop()) |e| switch (e.kind) {
            .wake, .fault => {},
            .net => |ev| sim.net.dropEvent(ev),
        };
        sim.events.deinit(sim.gpa);
        sim.net.deinit();
        for (sim.hosts.items) |h| {
            h.handles.deinit(sim.gpa);
            h.fs.deinit();
            h.releaseAll();
            h.live_allocs.deinit(sim.gpa);
            for (h.boots.items) |b| sim.gpa.rawFree(b.context, b.context_align, @returnAddress());
            h.boots.deinit(sim.gpa);
            sim.gpa.destroy(h);
        }
        sim.hosts.deinit(sim.gpa);
        sim.ready.deinit(sim.gpa);
        sim.futex_waiters.deinit(sim.gpa);
        for (sim.free_stacks.items) |s| stack_mod.unmap(s);
        sim.free_stacks.deinit(sim.gpa);
        sim.* = undefined;
    }

    pub fn addHost(sim: *Sim, opts: HostOptions) Allocator.Error!*Host {
        const h = try sim.gpa.create(Host);
        errdefer sim.gpa.destroy(h);
        const id: u32 = @intCast(sim.hosts.items.len);
        const n: u32 = id + 1;
        var ip6: [16]u8 = .{ 0xfd, 0 } ++ .{0} ** 14;
        std.mem.writeInt(u32, ip6[12..16], n, .big);
        h.* = .{
            .sim = sim,
            .id = id,
            .ip4 = opts.ip4 orelse .{ 10, @truncate(n >> 16), @truncate(n >> 8), @truncate(n) },
            .ip6 = opts.ip6 orelse ip6,
            // An independent stream per host, so adding a host does not
            // perturb the draws another host's code sees.
            .prng = .init(sim.opts.seed ^ (0x9e3779b97f4a7c15 *% (@as(u64, id) + 1))),
            .clock_skew_ns = opts.clock_skew_ns,
        };
        try h.fs.init(h, sim.opts.seed ^ (0xd15c_0000 +% @as(u64, id)), opts.disk_bytes);
        errdefer h.fs.deinit();
        try sim.hosts.append(sim.gpa, h);
        return h;
    }

    /// A digest of every scheduling decision and wake so far. Equal seeds and
    /// equal programs give equal fingerprints; a difference means the code
    /// under test is nondeterministic.
    pub fn fingerprint(sim: *const Sim) u64 {
        return sim.fingerprint_state;
    }

    /// Connects two hosts with a bidirectional link (or reconfigures and
    /// raises an existing one).
    pub fn link(sim: *Sim, a: *Host, b: *Host, cfg: net_mod.LinkConfig) Allocator.Error!void {
        return sim.net.link(a.id, b.id, cfg);
    }

    /// Links every pair of hosts added so far.
    pub fn linkAll(sim: *Sim, cfg: net_mod.LinkConfig) Allocator.Error!void {
        for (sim.hosts.items, 0..) |a, i| for (sim.hosts.items[i + 1 ..]) |b| try sim.link(a, b, cfg);
    }

    /// Takes a link down or brings it back up. Packets already in flight on
    /// a path that breaks are lost; streams retransmit until it heals.
    pub fn setLinkUp(sim: *Sim, a: *Host, b: *Host, up: bool) error{NoSuchLink}!void {
        return sim.net.setLinkUp(a.id, b.id, up);
    }

    /// One direction only: `from → to` stops carrying traffic while
    /// `to → from` still works.
    pub fn setLinkDirUp(sim: *Sim, from: *Host, to: *Host, up: bool) error{NoSuchLink}!void {
        return sim.net.setDirUp(from.id, to.id, up);
    }

    /// Splits the network: hosts in `cut` cannot reach the others until
    /// `heal` with the returned id.
    pub fn partition(sim: *Sim, cut: []const *Host) Allocator.Error!u32 {
        var ids: [256]u32 = undefined;
        assert(cut.len <= ids.len);
        for (cut, 0..) |h, i| ids[i] = h.id;
        sim.next_partition += 1;
        try sim.net.partition(sim.next_partition, ids[0..cut.len]);
        return sim.next_partition;
    }

    pub fn heal(sim: *Sim, id: u32) void {
        sim.net.heal(id);
    }

    /// Power cut: every task of `h` stops where it is (no unwinding, no
    /// `defer`), its sockets vanish without a FIN or a reset, memory from
    /// `h.allocator()` is released, and the host is unreachable until
    /// `restart`. Call it from the test between runs, from a fault schedule,
    /// or from a task of another host.
    pub fn crash(sim: *Sim, h: *Host) void {
        if (sim.current) |me| if (me.host == h) @panic("simio: a host cannot crash itself from one of its own tasks");
        if (!h.up) return;
        h.up = false;
        h.crashes += 1;
        sim.mix(0xc4a5_0000 + @as(u64, h.id));

        // Detach the host's tasks from everything that could wake them.
        var i: usize = 0;
        while (i < sim.ready.items.len) {
            if (sim.ready.items[i].host == h) _ = sim.ready.orderedRemove(i) else i += 1;
        }
        i = 0;
        while (i < sim.futex_waiters.items.len) {
            if (sim.futex_waiters.items[i].host == h) _ = sim.futex_waiters.orderedRemove(i) else i += 1;
        }
        // Their groups go with them (the root group's state, and any group
        // one of them created).
        var groups: std.AutoArrayHashMapUnmanaged(*GroupState, void) = .empty;
        defer groups.deinit(sim.gpa);
        if (h.root_group.token.raw) |token| groups.put(sim.gpa, @ptrCast(@alignCast(token)), {}) catch {};
        h.root_group = .init;
        i = sim.fibers.count();
        while (i > 0) {
            i -= 1;
            const f = sim.fibers.keys()[i];
            if (f.host != h) continue;
            if (f.group) |g| groups.put(sim.gpa, g, {}) catch {};
            if (f.wait == .group) groups.put(sim.gpa, f.wait.group, {}) catch {};
            sim.destroyFiber(f); // wake events still naming it are now stale
        }
        for (groups.keys()) |g| {
            g.members.deinit(sim.gpa);
            sim.gpa.destroy(g);
        }
        sim.net.crashHost(h);
        h.fs.crash();
        h.releaseAll();
    }

    /// Powers a crashed host back on: monotonic clocks restart from zero
    /// and every `spawnBoot` task starts again.
    pub fn restart(sim: *Sim, h: *Host) void {
        if (h.up) return;
        h.up = true;
        h.boot_ns = sim.now;
        sim.mix(0x7e57_0000 + @as(u64, h.id));
        for (h.boots.items) |b| {
            _ = sim.spawnGroupTask(h, &h.root_group, b.context, b.context_align, b.start) catch {};
        }
    }

    /// Runs until nothing can make progress (or the step limit). Callable
    /// again after spawning more tasks.
    pub fn run(sim: *Sim) RunResult {
        return sim.runUntil(null);
    }

    /// Runs for at most `duration_ns` of virtual time; returns `.time_limit`
    /// when that time is reached with work still pending.
    pub fn runFor(sim: *Sim, duration_ns: u64) RunResult {
        return sim.runUntil(sim.now +| duration_ns);
    }

    fn runUntil(sim: *Sim, limit: ?u64) RunResult {
        sim.assertOwner();
        assert(sim.current == null);
        while (true) {
            if (sim.steps >= sim.opts.max_steps) return sim.runResult(.step_limit);
            // Events due now (a fault scheduled for this instant, a timer
            // that just expired) happen before the next task step.
            const due = sim.fireDue();
            if (sim.ready.items.len == 0 and !due) {
                switch (sim.fireEvents(limit)) {
                    .fired => {},
                    .idle => break,
                    .limit => return sim.runResult(.time_limit),
                }
            } else if (sim.ready.items.len > 0) {
                const idx = switch (sim.opts.schedule) {
                    .fifo => 0,
                    .random => sim.prng.below(sim.ready.items.len),
                };
                const f = sim.ready.orderedRemove(idx);
                sim.steps += 1;
                sim.mix(f.id ^ (sim.now *% 0x9e3779b97f4a7c15));
                sim.switchTo(f);
                if (f.state == .done and f.task == .group) sim.destroyFiber(f);
            }
            if (sim.invariant) |inv| inv.check(sim, inv.ctx) catch |err| {
                var r = sim.runResult(.violated);
                r.violation = err;
                return r;
            };
        }
        return sim.runResult(if (sim.live == 0) .quiescent else .deadlock);
    }

    /// Checked after every task step and every batch of events; an error
    /// stops the run with `.violated`. Runs on the scheduler, not in a task:
    /// it may read shared state, it must not call `std.Io`.
    pub fn setInvariant(sim: *Sim, check: *const fn (sim: *Sim, ctx: ?*anyopaque) anyerror!void, ctx: ?*anyopaque) void {
        sim.invariant = .{ .check = check, .ctx = ctx };
    }

    fn runResult(sim: *const Sim, outcome: Outcome) RunResult {
        return .{
            .outcome = outcome,
            .steps = sim.steps,
            .blocked = if (outcome == .deadlock) sim.live else 0,
            .now_ns = sim.now,
        };
    }

    fn mix(sim: *Sim, v: u64) void {
        var p: Prng = .{ .state = sim.fingerprint_state ^ v };
        sim.fingerprint_state = p.next();
    }

    fn assertOwner(sim: *const Sim) void {
        if (std.debug.runtime_safety) assert(std.Thread.getCurrentId() == sim.owner);
    }

    // ── events ──────────────────────────────────────────────────────────────

    /// Advances virtual time to the earliest live event and fires every
    /// event due by then (including ones those events schedule for the same
    /// instant).
    fn fireEvents(sim: *Sim, limit: ?u64) enum { fired, idle, limit } {
        while (sim.events.peek()) |e| {
            if (sim.staleEvent(e)) {
                _ = sim.events.pop(); // that wait already ended
                continue;
            }
            if (limit) |l| if (e.at > l) {
                sim.now = @max(sim.now, l);
                return .limit;
            };
            if (e.at > sim.now) sim.now = e.at;
            break;
        } else {
            if (limit) |l| sim.now = @max(sim.now, l);
            return .idle;
        }
        while (sim.events.peek()) |e| {
            if (e.at > sim.now) break;
            _ = sim.events.pop();
            switch (e.kind) {
                .wake => |w| if (!sim.staleEvent(e)) sim.wake(w.fiber, .timeout),
                .net => |ev| {
                    sim.mix(e.seq);
                    sim.net.fire(ev);
                },
                .fault => |f| {
                    sim.mix(e.seq);
                    sim.applyFault(f);
                },
            }
        }
        return .fired;
    }

    /// Fires the events due at the current instant without advancing time.
    fn fireDue(sim: *Sim) bool {
        var fired = false;
        while (sim.events.peek()) |e| {
            if (e.at > sim.now) break;
            _ = sim.events.pop();
            if (sim.staleEvent(e)) continue;
            fired = true;
            switch (e.kind) {
                .wake => |w| sim.wake(w.fiber, .timeout),
                .net => |ev| {
                    sim.mix(e.seq);
                    sim.net.fire(ev);
                },
                .fault => |f| {
                    sim.mix(e.seq);
                    sim.applyFault(f);
                },
            }
        }
        return fired;
    }

    fn armTimer(sim: *Sim, f: *Fiber, at: u64) Allocator.Error!void {
        sim.seq += 1;
        try sim.events.push(sim.gpa, .{ .at = at, .seq = sim.seq, .kind = .{ .wake = .{ .fiber = f, .id = f.id, .gen = f.wait_gen } } });
    }

    fn staleEvent(sim: *const Sim, e: Event) bool {
        return switch (e.kind) {
            .wake => |w| !sim.fibers.contains(w.fiber) or w.fiber.id != w.id or
                w.gen != w.fiber.wait_gen or w.fiber.state != .blocked,
            .net, .fault => false,
        };
    }

    /// Schedules `fault` at virtual time `at_ns`.
    pub fn scheduleFault(sim: *Sim, at_ns: u64, fault: Fault) Allocator.Error!void {
        sim.seq += 1;
        try sim.events.push(sim.gpa, .{ .at = at_ns, .seq = sim.seq, .kind = .{ .fault = fault } });
    }

    /// Applies a fault now. Targets that do not exist are ignored, so a
    /// shrunk schedule stays well-formed.
    pub fn applyFault(sim: *Sim, fault: Fault) void {
        const hosts = sim.hosts.items;
        switch (fault) {
            .link_down => |l| sim.net.setDirUp(l.from, l.to, false) catch {},
            .link_up => |l| sim.net.setDirUp(l.from, l.to, true) catch {},
            .partition => |p| sim.net.partition(p.id, p.cut) catch {},
            .heal => |id| sim.net.heal(id),
            .crash => |i| if (i < hosts.len) sim.crash(hosts[i]),
            .restart => |i| if (i < hosts.len) sim.restart(hosts[i]),
            .clock_jump => |j| if (j.host < hosts.len) {
                hosts[j.host].clock_skew_ns += j.delta_ns;
            },
            .drop_once => |l| sim.net.armDrop(l.from, l.to),
            .dup_once => |l| sim.net.armDup(l.from, l.to),
            .delay_once => |l| sim.net.armDelay(l.from, l.to, l.extra_ns),
            .disk_error => |d| if (d.host < hosts.len) switch (d.op) {
                .read => hosts[d.host].fs.fail_read += 1,
                .write => hosts[d.host].fs.fail_write += 1,
                .sync => hosts[d.host].fs.fail_sync += 1,
            },
            .bit_rot => |i| if (i < hosts.len) hosts[i].fs.bitRot(),
        }
    }

    /// Queues a network event (internal, for `net.zig`).
    pub fn scheduleNet(sim: *Sim, at: u64, ev: net_mod.Event) Allocator.Error!void {
        sim.seq += 1;
        try sim.events.push(sim.gpa, .{ .at = at, .seq = sim.seq, .kind = .{ .net = ev } });
    }

    // ── fibers ──────────────────────────────────────────────────────────────

    fn takeStack(sim: *Sim) stack_mod.Error!stack_mod.Stack {
        if (sim.free_stacks.pop()) |s| return s;
        return stack_mod.map(sim.opts.stack_size);
    }

    fn createFiber(
        sim: *Sim,
        host: *Host,
        task: Task,
        context: []const u8,
        context_align: Alignment,
        result_len: usize,
        result_align: Alignment,
    ) error{OutOfMemory}!*Fiber {
        try sim.fibers.ensureUnusedCapacity(sim.gpa, 1);
        try sim.ready.ensureTotalCapacity(sim.gpa, sim.fibers.count() + 1);
        const f = try sim.gpa.create(Fiber);
        errdefer sim.gpa.destroy(f);
        const ctx_len = @max(context.len, 1);
        const ctx_ptr = sim.gpa.rawAlloc(ctx_len, context_align, @returnAddress()) orelse
            return error.OutOfMemory;
        const context_mem = ctx_ptr[0..ctx_len];
        errdefer sim.gpa.rawFree(context_mem, context_align, @returnAddress());
        const res_len = @max(result_len, 1);
        const res_ptr = sim.gpa.rawAlloc(res_len, result_align, @returnAddress()) orelse
            return error.OutOfMemory;
        const result_mem = res_ptr[0..res_len];
        errdefer sim.gpa.rawFree(result_mem, result_align, @returnAddress());
        const stack = try sim.takeStack();
        errdefer sim.free_stacks.append(sim.gpa, stack) catch stack_mod.unmap(stack);

        @memcpy(context_mem[0..context.len], context);
        f.* = .{
            .context = initialContext(stack, f),
            .sim = sim,
            .host = host,
            .id = sim.next_fiber_id,
            .state = .ready,
            .stack = stack,
            .task = task,
            .context_mem = context_mem,
            .context_align = context_align,
            .result_mem = result_mem,
            .result_align = result_align,
        };
        sim.next_fiber_id += 1;
        sim.fibers.putAssumeCapacity(f, {});
        sim.ready.appendAssumeCapacity(f);
        sim.live += 1;
        return f;
    }

    fn destroyFiber(sim: *Sim, f: *Fiber) void {
        assert(f != sim.current);
        if (f.state != .done) sim.live -= 1;
        _ = sim.fibers.swapRemove(f);
        sim.free_stacks.append(sim.gpa, f.stack) catch stack_mod.unmap(f.stack);
        sim.gpa.rawFree(f.context_mem, f.context_align, @returnAddress());
        sim.gpa.rawFree(f.result_mem, f.result_align, @returnAddress());
        sim.gpa.destroy(f);
    }

    /// The slot just below the stack top holds the `*Fiber` the trampoline
    /// hands to `fiberMain`; the initial stack pointer sits right under it.
    fn initialContext(stack: stack_mod.Stack, f: *Fiber) fiber.Context {
        const slot_addr = std.mem.alignBackward(usize, stack.top() - @sizeOf(*Fiber), 16);
        const slot: **Fiber = @ptrFromInt(slot_addr);
        slot.* = f;
        return switch (builtin.cpu.arch) {
            .x86_64 => .{ .rsp = slot_addr - 8, .rbp = 0, .rip = @intFromPtr(&entry) },
            .aarch64, .riscv64 => .{ .sp = slot_addr, .fp = 0, .pc = @intFromPtr(&entry) },
            else => unreachable,
        };
    }

    fn entry() callconv(.naked) void {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile (
                \\ leaq 8(%%rsp), %%rdi
                \\ jmp %[main:P]
                :
                : [main] "X" (&fiberMain),
            ),
            .aarch64 => asm volatile (
                \\ mov x0, sp
                \\ b %[main]
                :
                : [main] "X" (&fiberMain),
            ),
            .riscv64 => asm volatile (
                \\ mv a0, sp
                \\ tail %[main]@plt
                :
                : [main] "X" (&fiberMain),
            ),
            else => unreachable,
        }
    }

    fn fiberMain(slot: *const *Fiber) callconv(.withStackAlign(.c, 16)) noreturn {
        const f = slot.*;
        const sim = f.sim;
        switch (f.task) {
            .future => |start| start(f.context_mem.ptr, f.result_mem.ptr),
            .group => |start| start(f.context_mem.ptr),
        }
        f.state = .done;
        sim.live -= 1;
        switch (f.task) {
            .future => if (f.awaiter) |a| sim.wake(a, .normal),
            .group => sim.leaveGroup(f),
        }
        sim.toScheduler(f);
        unreachable; // a finished fiber is never switched to again
    }

    fn switchTo(sim: *Sim, f: *Fiber) void {
        assert(f.state == .ready);
        f.state = .running;
        sim.current = f;
        const sw: fiber.Switch = .{ .old = &sim.sched_context, .new = &f.context };
        _ = fiber.contextSwitch(&sw);
        sim.current = null;
    }

    fn toScheduler(sim: *Sim, f: *Fiber) void {
        const sw: fiber.Switch = .{ .old = &f.context, .new = &sim.sched_context };
        _ = fiber.contextSwitch(&sw);
    }

    /// The task calling into `Io` right now.
    pub fn running(sim: *Sim) *Fiber {
        return sim.current orelse
            @panic("simio: std.Io used outside a simulated task (call it from a task started by Host.spawn)");
    }

    /// Ends a task's wait (internal, for `net.zig`).
    pub fn wake(sim: *Sim, f: *Fiber, reason: WakeReason) void {
        assert(f.state == .blocked);
        switch (f.wait) {
            .futex => {
                for (sim.futex_waiters.items, 0..) |w, i| if (w == f) {
                    _ = sim.futex_waiters.orderedRemove(i);
                    break;
                };
            },
            .sock => |s| for (s.waiters.items, 0..) |w, i| if (w == f) {
                _ = s.waiters.orderedRemove(i);
                break;
            },
            .batch => sim.net.unwaitAll(f.host, f),
            else => {},
        }
        f.wait = .none;
        f.wait_gen += 1;
        f.wake_reason = reason;
        f.state = .ready;
        sim.mix(f.id ^ (@as(u64, @intFromEnum(reason)) << 60) ^ (sim.now *% 0xbf58476d1ce4e5b9));
        sim.ready.appendAssumeCapacity(f); // capacity invariant: see `fibers`
    }

    /// Parks the running task until something wakes it. Only arming a timer
    /// can fail; the wake itself never allocates. (Internal, for `net.zig`.)
    pub fn block(sim: *Sim, f: *Fiber, wait: Wait, cancelable: bool, deadline: ?u64) Allocator.Error!WakeReason {
        assert(f == sim.current);
        if (deadline) |at| try sim.armTimer(f, at);
        f.state = .blocked;
        f.wait = wait;
        f.cancelable = cancelable;
        sim.toScheduler(f);
        assert(f.state == .running);
        f.cancelable = false;
        return f.wake_reason;
    }

    /// A yield point: with `preempt_permille` the task goes to the back of
    /// the ready set and another task may run first.
    pub fn maybeYield(sim: *Sim, f: *Fiber) void {
        if (sim.opts.schedule == .fifo or !sim.prng.permille(sim.opts.preempt_permille)) return;
        sim.ready.appendAssumeCapacity(f); // capacity invariant: see `fibers`
        f.state = .ready;
        sim.toScheduler(f);
        assert(f.state == .running);
    }

    /// A cancelation point (internal, for `net.zig`).
    pub fn cancelPoint(sim: *Sim, f: *Fiber) error{Canceled}!void {
        _ = sim;
        if (f.cancelPending()) {
            f.acknowledge();
            return error.Canceled;
        }
    }

    /// Converts a `Timeout` on host `h` into an absolute virtual deadline.
    pub fn deadlineOf(sim: *const Sim, h: *const Host, timeout: Io.Timeout) ?u64 {
        const delta: i96 = switch (timeout) {
            .none => return null,
            .duration => |d| d.raw.nanoseconds,
            .deadline => |d| d.raw.nanoseconds - h.clockNs(d.clock),
        };
        const clamped: u64 = if (delta <= 0) 0 else @intCast(@min(delta, std.math.maxInt(u64) - sim.now));
        return sim.now + clamped;
    }

    // ── cancelation ─────────────────────────────────────────────────────────

    fn requestCancel(sim: *Sim, f: *Fiber) void {
        if (f.state == .done or f.cancel_requested) return;
        f.cancel_requested = true;
        if (f.state != .blocked or !f.cancelable or f.protection != .unblocked) return;
        switch (f.wait) {
            .futex, .sleep, .sock, .batch => sim.wake(f, .canceled),
            .group => |g| {
                // The awaiter keeps waiting; the request propagates to the
                // members and surfaces when the group is done.
                f.acknowledge();
                f.cancelable = false;
                g.awaiter_canceled = true;
                sim.cancelMembers(g);
            },
            .none, .await_future => unreachable, // not cancelable waits
        }
    }

    fn cancelMembers(sim: *Sim, g: *GroupState) void {
        g.cancel_all = true;
        // Waking a member cannot add or remove members, so iterating is safe.
        for (g.members.items) |m| sim.requestCancel(m);
    }

    // ── groups ──────────────────────────────────────────────────────────────

    fn groupState(sim: *Sim, group: *Io.Group) Allocator.Error!*GroupState {
        if (group.token.raw) |token| return @ptrCast(@alignCast(token));
        const g = try sim.gpa.create(GroupState);
        g.* = .{};
        group.token.raw = g;
        return g;
    }

    fn releaseGroup(sim: *Sim, group: *Io.Group, g: *GroupState) void {
        assert(g.members.items.len == 0);
        g.members.deinit(sim.gpa);
        sim.gpa.destroy(g);
        group.token.raw = null;
        group.state = 0;
    }

    fn spawnGroupTask(
        sim: *Sim,
        host: *Host,
        group: *Io.Group,
        context: []const u8,
        context_align: Alignment,
        start: *const fn (context: *const anyopaque) void,
    ) error{OutOfMemory}!*Fiber {
        const g = try sim.groupState(group);
        try g.members.ensureUnusedCapacity(sim.gpa, 1);
        const f = try sim.createFiber(host, .{ .group = start }, context, context_align, 0, .@"1");
        f.group = g;
        g.members.appendAssumeCapacity(f);
        if (g.cancel_all) sim.requestCancel(f);
        return f;
    }

    fn leaveGroup(sim: *Sim, f: *Fiber) void {
        const g = f.group.?;
        for (g.members.items, 0..) |m, i| if (m == f) {
            _ = g.members.swapRemove(i);
            break;
        };
        if (g.members.items.len == 0) if (g.awaiter) |a| {
            g.awaiter = null;
            sim.wake(a, .normal);
        };
    }

    // ── the vtable's concurrency entries ────────────────────────────────────

    pub fn concurrent(
        sim: *Sim,
        host: *Host,
        result_len: usize,
        result_align: Alignment,
        context: []const u8,
        context_align: Alignment,
        start: *const fn (context: *const anyopaque, result: *anyopaque) void,
    ) Io.ConcurrentError!*Io.AnyFuture {
        const f = sim.createFiber(host, .{ .future = start }, context, context_align, result_len, result_align) catch
            return error.ConcurrencyUnavailable;
        if (sim.current) |me| sim.maybeYield(me);
        return @ptrCast(f);
    }

    pub fn await(sim: *Sim, any_future: *Io.AnyFuture, result: []u8, result_align: Alignment) void {
        const me = sim.running();
        const f: *Fiber = @ptrCast(@alignCast(any_future));
        assert(f.task == .future and f.awaiter == null);
        if (f.state != .done) {
            f.awaiter = me;
            _ = sim.block(me, .await_future, false, null) catch
                @panic("simio: out of memory while awaiting a task");
        }
        assert(f.state == .done);
        assert(result_align == f.result_align);
        @memcpy(result, f.result_mem[0..result.len]);
        sim.destroyFiber(f);
    }

    pub fn cancel(sim: *Sim, any_future: *Io.AnyFuture, result: []u8, result_align: Alignment) void {
        const f: *Fiber = @ptrCast(@alignCast(any_future));
        sim.requestCancel(f);
        sim.await(any_future, result, result_align);
    }

    pub fn groupAsync(
        sim: *Sim,
        host: *Host,
        group: *Io.Group,
        context: []const u8,
        context_align: Alignment,
        start: *const fn (context: *const anyopaque) void,
    ) void {
        _ = sim.spawnGroupTask(host, group, context, context_align, start) catch {
            // No unit of concurrency: run it now, as the contract allows.
            start(context.ptr);
            return;
        };
        if (sim.current) |me| sim.maybeYield(me);
    }

    pub fn groupConcurrent(
        sim: *Sim,
        host: *Host,
        group: *Io.Group,
        context: []const u8,
        context_align: Alignment,
        start: *const fn (context: *const anyopaque) void,
    ) Io.ConcurrentError!void {
        _ = sim.spawnGroupTask(host, group, context, context_align, start) catch
            return error.ConcurrencyUnavailable;
        if (sim.current) |me| sim.maybeYield(me);
    }

    pub fn groupAwait(sim: *Sim, group: *Io.Group, token: *anyopaque) Io.Cancelable!void {
        const me = sim.running();
        const g: *GroupState = @ptrCast(@alignCast(token));
        var canceled = false;
        if (me.cancelPending()) {
            me.acknowledge();
            canceled = true;
            sim.cancelMembers(g);
        }
        if (g.members.items.len != 0) {
            g.awaiter = me;
            g.awaiter_canceled = false;
            _ = sim.block(me, .{ .group = g }, !canceled, null) catch
                @panic("simio: out of memory while awaiting a group");
            if (g.awaiter_canceled) canceled = true;
        }
        sim.releaseGroup(group, g);
        if (canceled) return error.Canceled;
    }

    pub fn groupCancel(sim: *Sim, group: *Io.Group, token: *anyopaque) void {
        const me = sim.running();
        const g: *GroupState = @ptrCast(@alignCast(token));
        sim.cancelMembers(g);
        if (g.members.items.len != 0) {
            g.awaiter = me;
            _ = sim.block(me, .{ .group = g }, false, null) catch
                @panic("simio: out of memory while canceling a group");
        }
        sim.releaseGroup(group, g);
    }

    pub fn recancel(sim: *Sim) void {
        const me = sim.running();
        assert(me.cancel_requested and me.cancel_acked);
        me.cancel_acked = false;
    }

    pub fn swapCancelProtection(sim: *Sim, new: Io.CancelProtection) Io.CancelProtection {
        const me = sim.running();
        const old = me.protection;
        me.protection = new;
        return old;
    }

    pub fn checkCancel(sim: *Sim) Io.Cancelable!void {
        const me = sim.running();
        if (me.cancelPending()) {
            me.acknowledge();
            return error.Canceled;
        }
        sim.maybeYield(me);
    }

    // ── futex ───────────────────────────────────────────────────────────────

    pub fn futexWait(sim: *Sim, ptr: *const u32, expected: u32, timeout: Io.Timeout, cancelable: bool) Io.Cancelable!void {
        const me = sim.running();
        if (cancelable and me.cancelPending()) {
            me.acknowledge();
            return error.Canceled;
        }
        if (@atomicLoad(u32, ptr, .monotonic) != expected) return;
        sim.futex_waiters.ensureUnusedCapacity(sim.gpa, 1) catch return; // a spurious wakeup is allowed
        sim.futex_waiters.appendAssumeCapacity(me);
        const reason = sim.block(me, .{ .futex = ptr }, cancelable, sim.deadlineOf(me.host, timeout)) catch {
            _ = sim.futex_waiters.pop();
            return;
        };
        if (reason == .canceled) {
            me.acknowledge();
            return error.Canceled;
        }
    }

    pub fn futexWake(sim: *Sim, ptr: *const u32, max_waiters: u32) void {
        var woken: u32 = 0;
        var i: usize = 0;
        while (i < sim.futex_waiters.items.len and woken < max_waiters) {
            const w = sim.futex_waiters.items[i];
            if (w.wait.futex != ptr) {
                i += 1;
                continue;
            }
            sim.wake(w, .normal); // removes it from `futex_waiters`
            woken += 1;
        }
        if (sim.current) |me| sim.maybeYield(me);
    }

    // ── time and randomness ─────────────────────────────────────────────────

    pub fn sleep(sim: *Sim, timeout: Io.Timeout) Io.Cancelable!void {
        const me = sim.running();
        if (me.cancelPending()) {
            me.acknowledge();
            return error.Canceled;
        }
        const reason = sim.block(me, .sleep, true, sim.deadlineOf(me.host, timeout)) catch
            @panic("simio: out of memory while sleeping");
        if (reason == .canceled) {
            me.acknowledge();
            return error.Canceled;
        }
    }

    pub fn random(sim: *Sim, host: *Host, buffer: []u8) void {
        _ = sim;
        var i: usize = 0;
        while (i < buffer.len) {
            const word = host.prng.next();
            const n = @min(8, buffer.len - i);
            @memcpy(buffer[i..][0..n], std.mem.asBytes(&word)[0..n]);
            i += n;
        }
    }
};
