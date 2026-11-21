// SPDX-License-Identifier: MIT

//! `HandlerPool`: a bounded worker pool for gRPC handlers, wired into
//! `Router.pool`. Without one a connection's streams run one after another on
//! the connection's own task, so a handler blocked on a database or a queue
//! stops that connection reading at all (PING, SETTINGS and every other stream
//! included). With one each stream's handler runs on a worker thread and the
//! connection task goes back to reading, which is what grpc-go (a goroutine per
//! stream) and tonic (a task per stream) do by default.
//!
//! Two caps, as `http.h2_server.Dispatcher` documents: `per_connection`
//! handlers at once for one connection (the rest wait in the connection's
//! already-bounded stream table) and `global_cap` for the whole pool, over
//! which a new stream is refused with `RST_STREAM(REFUSED_STREAM)` (retryable,
//! HTTP/2 §8.7) rather than queued. The `gpa` of the `Router` must then be
//! thread-safe, and so must the handlers.

const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http");
const workerpool = @import("workerpool");

pub const Options = struct {
    /// Worker threads; null = one per CPU.
    workers: ?usize = null,
    /// Handlers running at once for one connection.
    per_connection: u32 = 8,
    /// Handlers running or about to run in the whole pool; null = 4 per CPU.
    global_cap: ?u32 = null,
};

pub const HandlerPool = struct {
    gpa: Allocator,
    pool: *workerpool.WorkerPool,
    per_connection: u32,
    global_cap: u32,
    live: std.atomic.Value(u32) = .init(0),

    const Slot = struct { p: *HandlerPool, task: http.h2_server.Task };

    /// Start the pool. `io` is the `std.Io` the workers park on (the one the
    /// server uses). Heap-allocated: the dispatcher keeps a pointer to it.
    pub fn init(gpa: Allocator, io: std.Io, options: Options) !*HandlerPool {
        const p = try gpa.create(HandlerPool);
        errdefer gpa.destroy(p);
        const cpus = std.Thread.getCpuCount() catch 1;
        p.* = .{
            .gpa = gpa,
            .pool = try workerpool.WorkerPool.init(gpa, .{ .io = io, .n_workers = options.workers }),
            .per_connection = @max(1, options.per_connection),
            .global_cap = options.global_cap orelse @intCast(@max(1, cpus * 4)),
        };
        return p;
    }

    /// Wait for the running handlers, stop the workers, free the pool. Stop
    /// serving first: a stream that arrives now is refused.
    pub fn deinit(p: *HandlerPool) void {
        p.pool.drain();
        p.pool.deinit();
        p.gpa.destroy(p);
    }

    /// The `http` dispatcher over this pool (what `Router.pool` installs).
    pub fn dispatcher(p: *HandlerPool) http.h2_server.Dispatcher {
        return .{ .ctx = p, .spawn = spawn, .max_concurrent_handlers = p.per_connection };
    }

    fn spawn(ctx: ?*anyopaque, task: http.h2_server.Task) bool {
        const p: *HandlerPool = @ptrCast(@alignCast(ctx.?));
        // Reserve the global slot before enqueueing: a full pool refuses, it
        // never grows a queue behind itself.
        while (true) {
            const cur = p.live.load(.monotonic);
            if (cur >= p.global_cap) return false;
            if (p.live.cmpxchgWeak(cur, cur + 1, .acq_rel, .monotonic) == null) break;
        }
        const slot = p.gpa.create(Slot) catch {
            _ = p.live.fetchSub(1, .acq_rel);
            return false;
        };
        slot.* = .{ .p = p, .task = task };
        p.pool.submit(.{ .func = run, .ctx = slot }) catch {
            p.gpa.destroy(slot);
            _ = p.live.fetchSub(1, .acq_rel);
            return false;
        };
        return true;
    }

    fn run(ctx: *anyopaque) void {
        const slot: *Slot = @ptrCast(@alignCast(ctx));
        const p = slot.p;
        const task = slot.task;
        p.gpa.destroy(slot);
        task.func(task.ctx);
        _ = p.live.fetchSub(1, .acq_rel);
    }
};
