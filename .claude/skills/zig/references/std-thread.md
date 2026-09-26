# std.Thread - Threading and Concurrency API Reference (0.16)

Thread spawning and synchronization in Zig 0.16.

## Critical: Sync Primitives Removed From std.Thread (0.16)

`std.Thread.Mutex`, `std.Thread.Mutex.Recursive`, `std.Thread.Condition`, `std.Thread.RwLock`, `std.Thread.Semaphore`, `std.Thread.Futex`, `std.Thread.Pool`, `std.Thread.WaitGroup`, `std.Thread.ResetEvent`, and `std.Thread.sleep` are **all removed** from `std.Thread`. Only `std.Thread.spawn` and the thread-identity/utility functions (`getCurrentId`, `getCpuCount`, `yield`, `setName`/`getName`) remain there, unchanged.

Where things moved:

| 0.15.x | 0.16 |
|--------|------|
| `std.Thread.Mutex` | `std.Io.Mutex` (needs `io: Io` on every call) |
| `std.Thread.Condition` | `std.Io.Condition` (needs `io`) |
| `std.Thread.RwLock` | `std.Io.RwLock` (needs `io`) |
| `std.Thread.Semaphore` | `std.Io.Semaphore` (needs `io`) |
| `std.Thread.Futex` | `io.futexWait`/`io.futexWake` methods on `Io` (needs `io`); or the raw `std.os.linux.futex` syscall if you have no `Io` |
| `std.Thread.ResetEvent` | `std.Io.Event` (needs `io`) |
| `std.Thread.WaitGroup` + `std.Thread.Pool` | `std.Io.Group` (`group.async(io, fn, args)` / `group.await(io)`), backed by an `Io.Threaded` instance instead of a separately-managed pool |
| `std.Thread.sleep` | `io.sleep(duration, clock)`, or raw `std.c.nanosleep` with no `Io` |

**POSIX shims (last resort — code with no `Io` that already links libc):**

```zig
const PthreadMutex = struct {
    inner: std.c.pthread_mutex_t = std.c.PTHREAD_MUTEX_INITIALIZER,
    pub fn lock(m: *@This()) void { _ = std.c.pthread_mutex_lock(&m.inner); }
    pub fn unlock(m: *@This()) void { _ = std.c.pthread_mutex_unlock(&m.inner); }
    pub fn tryLock(m: *@This()) bool {
        return @intFromEnum(std.c.pthread_mutex_trylock(&m.inner)) == 0;
    }
};

const PthreadCondition = struct {
    inner: std.c.pthread_cond_t = std.c.PTHREAD_COND_INITIALIZER,
    pub fn signal(c: *@This()) void { _ = std.c.pthread_cond_signal(&c.inner); }
    pub fn broadcast(c: *@This()) void { _ = std.c.pthread_cond_broadcast(&c.inner); }
    pub fn timedWait(cond: *@This(), mutex: *PthreadMutex, timeout_ns: u64) !void {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.REALTIME, &ts);
        const now_ns: u128 = @as(u128, @intCast(ts.sec)) * 1_000_000_000 +
                              @as(u128, @intCast(ts.nsec));
        const deadline = std.c.timespec{
            .sec = @intCast((now_ns + timeout_ns) / 1_000_000_000),
            .nsec = @intCast((now_ns + timeout_ns) % 1_000_000_000),
        };
        const rc = std.c.pthread_cond_timedwait(&cond.inner, &mutex.inner, &deadline);
        if (@intFromEnum(rc) == @intFromEnum(std.c.E.TIMEDOUT)) return error.Timeout;
    }
};

// nanosleep with no Io, already linking libc (no Io.sleep available)
fn threadSleep(ns: u64) void {
    const ts = std.c.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.c.nanosleep(&ts, null);
}
```

For library code with no `Io` and no libc, a Linux-only fallback is the raw futex syscall, `std.os.linux.futex(...)`, which still exists (see `std.os` reference).

## Table of Contents
- [Module Structure](#module-structure)
- [Spawning Threads](#spawning-threads)
- [Thread Utilities](#thread-utilities)
- [Synchronization Primitives](#synchronization-primitives)
  - [Mutex](#mutex)
  - [RwLock](#rwlock)
  - [Condition](#condition)
  - [Semaphore](#semaphore)
  - [Event (was ResetEvent)](#event-was-resetevent)
  - [Group (was WaitGroup / Pool)](#group-was-waitgroup--pool)
- [Common Patterns](#common-patterns)

## Module Structure

```zig
std.Thread                  // Thread spawning and management — unchanged in 0.16
std.Io.Mutex                 // Mutual exclusion lock (needs io)
std.Io.RwLock                // Reader-writer lock (needs io)
std.Io.Condition             // Condition variable for signaling (needs io)
std.Io.Semaphore             // Counting semaphore (needs io)
std.Io.Event                 // Boolean event flag with blocking wait (needs io) — was Thread.ResetEvent
std.Io.Group                 // Spawn + await a set of tasks (needs io) — was Thread.WaitGroup / Thread.Pool
```

## Spawning Threads

### Basic Thread Spawn

```zig
const std = @import("std");

fn workerFn(id: usize) void {
    std.debug.print("Worker {d} running\n", .{id});
}

pub fn main() !void {
    const thread = try std.Thread.spawn(.{}, workerFn, .{42});
    thread.join();  // wait for completion
}
```

### Thread with Return Value

```zig
fn compute(x: i32) void {
    // Zig threads don't return values directly
    // Use shared state or channels for results
}
```

### Detached Threads

```zig
const thread = try std.Thread.spawn(.{}, workerFn, .{1});
thread.detach();  // thread cleans up itself on completion
// Cannot call join() after detach()
```

### Spawn Configuration

```zig
const thread = try std.Thread.spawn(.{
    .stack_size = 8 * 1024 * 1024,  // 8 MB stack (default: 16 MB)
    .allocator = allocator,          // required on WASI
}, workerFn, .{args});
```

### Thread Function Signatures

```zig
// Valid return types: void, !void, u8, noreturn
fn worker1() void { }
fn worker2() !void { return error.Failed; }
fn worker3() u8 { return 0; }  // exit status (ignored on pthreads)
fn worker4() noreturn { while (true) {} }
```

## Thread Utilities

### Get Current Thread ID

```zig
const id = std.Thread.getCurrentId();
std.debug.print("Thread ID: {d}\n", .{id});
```

### Get CPU Count

```zig
const cpu_count = std.Thread.getCpuCount() catch 1;
std.debug.print("CPUs: {d}\n", .{cpu_count});
```

### Sleep

**Note (0.16):** `std.Thread.sleep` is removed. With an `Io` instance, use `io.sleep(duration, clock)`; without one, `nanosleep` via `std.c.nanosleep` (see migration section above).

```zig
try io.sleep(.fromMilliseconds(100), .awake);  // sleep 100ms
try io.sleep(.fromSeconds(1), .awake);          // sleep 1 second
```

### Yield

```zig
std.Thread.yield() catch {};  // hint to scheduler
```

### Thread Names (Platform-dependent)

```zig
var thread = try std.Thread.spawn(.{}, worker, .{});

// Set thread name (max length varies by OS) — needs an `io: Io` in 0.16
try thread.setName(io, "worker-1");

// Get thread name
var name_buf: [std.Thread.max_name_len:0]u8 = undefined;
if (try thread.getName(&name_buf)) |name| {
    std.debug.print("Thread name: {s}\n", .{name});
}
```

## Synchronization Primitives

### Mutex

**Note (0.16):** `std.Thread.Mutex` is removed. Use `std.Io.Mutex`, which needs an `io: Io` on `lock`/`unlock`. There is no `Mutex.Recursive` anymore — restructure to avoid recursive locking, or track ownership manually.

Basic mutual exclusion lock. Use `defer` for exception-safe unlocking.

```zig
var mutex: std.Io.Mutex = .init;
var shared_data: u64 = 0;

fn increment(io: std.Io) !void {
    try mutex.lock(io);
    defer mutex.unlock(io);
    shared_data += 1;
}

// tryLock for non-blocking acquisition (no `io` needed — never blocks)
if (mutex.tryLock()) {
    defer mutex.unlock(io);
    // critical section
} else {
    // lock not acquired
}
```

### RwLock

Reader-writer lock: multiple readers OR one writer. Moved to `std.Io.RwLock` — same shape, every method now takes `io: Io` (except the non-blocking `tryLock*` variants).

```zig
var rwlock: std.Io.RwLock = .init;
var data: []const u8 = "initial";

fn reader(io: std.Io) !void {
    try rwlock.lockShared(io);
    defer rwlock.unlockShared(io);
    // read data safely (multiple readers allowed)
    _ = data;
}

fn writer(io: std.Io, new_data: []const u8) !void {
    try rwlock.lock(io);
    defer rwlock.unlock(io);
    // exclusive write access
    data = new_data;
}

// Non-blocking variants (no `io` needed)
if (rwlock.tryLockShared()) {
    defer rwlock.unlockShared(io);
    // read
}

if (rwlock.tryLock()) {
    defer rwlock.unlock(io);
    // write
}
```

### Condition

**Note (0.16):** `std.Thread.Condition` is removed. Use `std.Io.Condition`, which needs `io: Io`. There is no built-in `timedWait` — a bounded wait needs a separate timeout mechanism layered on top of `wait` (e.g. racing against `io.sleep` via `Io.Group`), not shown here.

Wait for a condition to become true. Always use with a Mutex.

```zig
var mutex: std.Io.Mutex = .init;
var cond: std.Io.Condition = .init;
var ready = false;

fn consumer(io: std.Io) !void {
    try mutex.lock(io);
    defer mutex.unlock(io);

    // Wait in a loop (handles spurious wakeups)
    while (!ready) {
        try cond.wait(io, &mutex);  // atomically unlocks, waits, relocks
    }
    // Process data
}

fn producer(io: std.Io) !void {
    {
        try mutex.lock(io);
        defer mutex.unlock(io);
        ready = true;
    }
    cond.signal(io);     // wake one waiter
    // cond.broadcast(io); // wake all waiters
}
```

### Semaphore

Counting semaphore for resource limiting. Moved to `std.Io.Semaphore`; `wait`/`post` take `io: Io`. There is no built-in `timedWait`.

```zig
var sem: std.Io.Semaphore = .{ .permits = 3 };  // 3 permits available

fn worker(io: std.Io) !void {
    try sem.wait(io);     // acquire permit (blocks if 0)
    defer sem.post(io);  // release permit
    // use limited resource
}
```

### Event (was ResetEvent)

Boolean flag with blocking wait. Useful for one-shot signaling. `std.Thread.ResetEvent` is gone; the replacement is `std.Io.Event`, whose methods take `io: Io` (except `isSet`/`reset`, which never block).

```zig
var event: std.Io.Event = .unset;

fn waiter(io: std.Io) !void {
    try event.wait(io);  // blocks until set
    // event.isSet() returns true
}

fn signaler(io: std.Io) void {
    event.set(io);   // unblocks all waiters
}

// Reset for reuse (only valid with no pending wait)
event.reset();

// Check without blocking
if (event.isSet()) {
    // already signaled
}

// Timed wait — Io.Timeout.duration takes a Clock.Duration (raw duration + which clock)
event.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } }) catch |err| switch (err) {
    error.Timeout => { /* handle timeout */ },
    error.Canceled => return err,
};
```

### Group (was WaitGroup / Pool)

`std.Thread.WaitGroup` and `std.Thread.Pool` are both gone. `std.Io.Group` replaces both: it spawns tasks through the `Io` implementation's own thread pool (e.g. `std.Io.Threaded`) and lets you wait for all of them.

```zig
var group: std.Io.Group = .init;

fn task(id: usize) void {
    // do work
    _ = id;
}

pub fn spawnTasks(io: std.Io) !void {
    for (0..10) |i| {
        group.async(io, task, .{i});  // spawns on the Io's own pool
    }
    try group.await(io);  // blocks until all tasks finish (or a cancelation propagates)
}
```

`Group.concurrent(io, fn, args)` is the "must actually run concurrently, or fail" variant of `.async` (returns `error.ConcurrencyUnavailable` instead of silently running inline). There is no separate `n_jobs`/pool-size knob here — that's configured once, on the `Io.Threaded` instance itself (`InitOptions.async_limit`/`concurrent_limit`).

## Common Patterns

### Producer-Consumer Queue

```zig
fn BoundedQueue(comptime T: type, comptime capacity: usize) type {
    return struct {
        buffer: [capacity]T = undefined,
        head: usize = 0,
        tail: usize = 0,
        count: usize = 0,

        mutex: std.Io.Mutex = .init,
        not_empty: std.Io.Condition = .init,
        not_full: std.Io.Condition = .init,

        pub fn push(self: *@This(), io: std.Io, item: T) !void {
            try self.mutex.lock(io);
            defer self.mutex.unlock(io);

            while (self.count == capacity) {
                try self.not_full.wait(io, &self.mutex);
            }

            self.buffer[self.tail] = item;
            self.tail = (self.tail + 1) % capacity;
            self.count += 1;

            self.not_empty.signal(io);
        }

        pub fn pop(self: *@This(), io: std.Io) !T {
            try self.mutex.lock(io);
            defer self.mutex.unlock(io);

            while (self.count == 0) {
                try self.not_empty.wait(io, &self.mutex);
            }

            const item = self.buffer[self.head];
            self.head = (self.head + 1) % capacity;
            self.count -= 1;

            self.not_full.signal(io);
            return item;
        }
    };
}
```

### Thread-Safe Counter

```zig
const Counter = struct {
    value: std.atomic.Value(u64) = .init(0),

    pub fn increment(self: *@This()) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    pub fn get(self: *const @This()) u64 {
        return self.value.load(.monotonic);
    }
};
```

### Parallel Map

```zig
fn parallelMap(
    io: std.Io,
    allocator: std.mem.Allocator,
    comptime T: type,
    comptime U: type,
    items: []const T,
    comptime mapFn: fn (T) U,
) ![]U {
    const results = try allocator.alloc(U, items.len);
    var group: std.Io.Group = .init;

    for (items, 0..) |item, i| {
        group.async(io, struct {
            fn work(r: []U, idx: usize, val: T) void {
                r[idx] = mapFn(val);
            }
        }.work, .{ results, i, item });
    }

    try group.await(io);
    return results;
}
```

### Once Initialization

```zig
var initialized = std.atomic.Value(bool).init(false);
var init_mutex: std.Io.Mutex = .init;
var global_resource: ?*Resource = null;

fn getResource(io: std.Io) !*Resource {
    // Fast path: already initialized
    if (initialized.load(.acquire)) {
        return global_resource.?;
    }

    try init_mutex.lock(io);
    defer init_mutex.unlock(io);

    // Double-check after acquiring lock
    if (!initialized.load(.acquire)) {
        global_resource = initializeResource();
        initialized.store(true, .release);
    }

    return global_resource.?;
}
```

### Barrier Synchronization

```zig
const Barrier = struct {
    event: std.Io.Event = .unset,
    counter: std.atomic.Value(usize),

    pub fn init(count: usize) @This() {
        return .{ .counter = std.atomic.Value(usize).init(count) };
    }

    pub fn wait(self: *@This(), io: std.Io) !void {
        if (self.counter.fetchSub(1, .acq_rel) == 1) {
            self.event.set(io);  // last thread signals all
        } else {
            try self.event.wait(io);  // others wait
        }
    }
};
```

### Scoped Lock Helper

```zig
fn withLock(io: std.Io, mutex: *std.Io.Mutex, comptime func: anytype, args: anytype) !@TypeOf(@call(.auto, func, args)) {
    try mutex.lock(io);
    defer mutex.unlock(io);
    return @call(.auto, func, args);
}

// Usage
const result = try withLock(io, &mutex, computeValue, .{x, y});
```

### Thread-Local Storage

```zig
threadlocal var tls_buffer: [1024]u8 = undefined;
threadlocal var tls_counter: usize = 0;

fn perThreadWork() void {
    tls_counter += 1;  // each thread has its own counter
    // use tls_buffer for thread-local scratch space
}
```
