// SPDX-License-Identifier: MIT

//! `KvBackend` and the `Backend` seam: a record that survives closing and
//! reopening the `kv` file, the in-flight 409, lease takeover, expiry on kv's
//! clock, fail-closed on a corrupt record, and the order in which a `Store`
//! drives a backend through the middleware (lookup, put, release).

const std = @import("std");
const testing = std.testing;
const kv = @import("kv");
const router = @import("router");
const http = @import("http");
const root = @import("root.zig");
const Store = root.Store;
const KvBackend = root.KvBackend;
const Backend = root.Backend;

const Clock = struct {
    now: i64 = 1_000_000,
    fn read(ctx: ?*anyopaque) i64 {
        const c: *Clock = @ptrCast(@alignCast(ctx.?));
        return c.now;
    }
    fn kvClock(c: *Clock) kv.Clock {
        return .{ .ctx = c, .nowFn = read };
    }
    fn storeClock(c: *Clock) root.Clock {
        return .{ .ctx = c, .nowFn = read };
    }
};

const digest_a: [32]u8 = @splat(0xaa);
const digest_b: [32]u8 = @splat(0xbb);

fn openDb(sim: *kv.SimStorage, clk: *Clock) !kv.Db {
    return kv.Db.open(testing.allocator, sim.storage(), "idem.kv", .{ .clock = clk.kvClock() });
}

test "KvBackend: a record survives closing and reopening the kv file" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var clk: Clock = .{};
    {
        var db = try openDb(&sim, &clk);
        defer db.close();
        var kb = KvBackend{ .db = &db, .gpa = testing.allocator };
        defer kb.deinit();
        var store = Store{ .backend = kb.backend(), .clock = clk.storeClock(), .ttl_ns = 60 * std.time.ns_per_s };
        defer store.deinit();
        try testing.expect((try store.begin("POST /charge\x00k1", digest_a, null, testing.allocator)) == .reserved);
        store.record("POST /charge\x00k1", digest_a, 201, "application/json", "{\"id\":7}");
        store.finish("POST /charge\x00k1", null);
    }
    // Reopen the file -- a new process. (That an acknowledged kv put
    // survives a crash is kv's own tested property: fsync before return.)
    var db = try openDb(&sim, &clk);
    defer db.close();
    var kb = KvBackend{ .db = &db, .gpa = testing.allocator };
    defer kb.deinit();
    var store = Store{ .backend = kb.backend(), .clock = clk.storeClock(), .ttl_ns = 60 * std.time.ns_per_s };
    defer store.deinit();
    switch (try store.begin("POST /charge\x00k1", digest_a, null, testing.allocator)) {
        .replay => |blob| {
            defer testing.allocator.free(blob);
            const rec = root.decode(blob).?;
            try testing.expectEqual(@as(u16, 201), rec.status);
            try testing.expectEqualStrings("application/json", rec.content_type);
            try testing.expectEqualStrings("{\"id\":7}", rec.body);
        },
        else => return error.TestExpectedReplay,
    }
    // A different body under the key: 422, the record stays.
    try testing.expect((try store.begin("POST /charge\x00k1", digest_b, null, testing.allocator)) == .mismatch);
    // Expiry is on kv's wall clock, stored on disk: 61 s later it is gone.
    clk.now += 61 * std.time.ms_per_s;
    try testing.expect((try store.begin("POST /charge\x00k1", digest_b, null, testing.allocator)) == .reserved);
    store.finish("POST /charge\x00k1", null);
}

test "KvBackend: a concurrent first-flight is 409 until released; a lease hands over a stale reservation" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var clk: Clock = .{};
    var db = try openDb(&sim, &clk);
    defer db.close();
    var kb = KvBackend{ .db = &db, .gpa = testing.allocator };
    defer kb.deinit();
    var store = Store{ .backend = kb.backend(), .clock = clk.storeClock() };
    defer store.deinit();
    var req1: u8 = 0;
    try testing.expect((try store.begin("k", digest_a, &req1, testing.allocator)) == .reserved);
    try testing.expectEqualStrings("k", store.current(&req1).?.key);
    try testing.expect((try store.begin("k", digest_a, null, testing.allocator)) == .in_flight);
    store.finish("k", &req1);
    try testing.expect(store.current(&req1) == null);
    // Released without a record: the next request runs.
    try testing.expect((try store.begin("k", digest_a, null, testing.allocator)) == .reserved);

    // Lease: no takeover before it runs out, takeover the instant it does
    // (age == lease), and the taker holds a fresh lease: a third request
    // right after is 409, not a second takeover (two runs at once).
    store.lease_ns = 500;
    clk.now += 499;
    try testing.expect((try store.begin("k", digest_a, null, testing.allocator)) == .in_flight);
    clk.now += 1;
    try testing.expect((try store.begin("k", digest_a, null, testing.allocator)) == .reserved);
    clk.now += 1;
    try testing.expect((try store.begin("k", digest_a, null, testing.allocator)) == .in_flight);
    store.finish("k", null);
    try testing.expectEqual(@as(usize, 0), kb.in_flight.count());
}

test "KvBackend: an unreadable record fails closed (409), never a second run" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var clk: Clock = .{};
    var db = try openDb(&sim, &clk);
    defer db.close();
    var kb = KvBackend{ .db = &db, .gpa = testing.allocator };
    defer kb.deinit();
    var store = Store{ .backend = kb.backend(), .clock = clk.storeClock() };
    defer store.deinit();
    try testing.expect((try store.begin("k", digest_a, null, testing.allocator)) == .reserved);
    store.record("k", digest_a, 200, "", "RECORDED-BODY");
    store.finish("k", null);
    // Rot one byte of the recorded body on the media: kv's read CRC check fails.
    const at = std.mem.find(u8, sim.fileContent("idem.kv").?, "RECORDED-BODY").?;
    sim.flipByte("idem.kv", at);
    try testing.expect((try store.begin("k", digest_a, null, testing.allocator)) == .in_flight);
    try testing.expectEqual(@as(u64, 1), kb.read_errors);
    try testing.expectEqual(@as(usize, 0), kb.in_flight.count());
}

/// A backend that logs its calls, over a plain map: checks how a `Store`
/// drives the seam through the real middleware.
const LogBackend = struct {
    log: std.ArrayList(u8) = .empty,
    records: std.StringHashMapUnmanaged([]u8) = .empty,
    held: bool = false,

    fn backend(self: *LogBackend) Backend {
        return .{ .ptr = self, .vtable = &.{ .lookupOrReserve = lookup, .put = put, .release = release }, .gpa = testing.allocator };
    }
    fn deinit(self: *LogBackend) void {
        var it = self.records.iterator();
        while (it.next()) |e| {
            testing.allocator.free(e.key_ptr.*);
            testing.allocator.free(e.value_ptr.*);
        }
        self.records.deinit(testing.allocator);
        self.log.deinit(testing.allocator);
    }
    fn lookup(ptr: *anyopaque, key: []const u8, now: i64, lease_ns: i64, gpa: std.mem.Allocator) std.mem.Allocator.Error!Backend.Lookup {
        _ = now;
        _ = lease_ns;
        const self: *LogBackend = @ptrCast(@alignCast(ptr));
        try self.log.append(testing.allocator, 'L');
        if (self.records.get(key)) |v| return .{ .found = try gpa.dupe(u8, v) };
        if (self.held) return .in_flight;
        self.held = true;
        return .reserved;
    }
    fn put(ptr: *anyopaque, key: []const u8, blob: []const u8, now: i64, ttl_ns: i64) void {
        _ = now;
        _ = ttl_ns;
        const self: *LogBackend = @ptrCast(@alignCast(ptr));
        self.log.append(testing.allocator, 'P') catch {};
        const k = testing.allocator.dupe(u8, key) catch return;
        const v = testing.allocator.dupe(u8, blob) catch return;
        self.records.put(testing.allocator, k, v) catch return;
    }
    fn release(ptr: *anyopaque, key: []const u8) void {
        _ = key;
        const self: *LogBackend = @ptrCast(@alignCast(ptr));
        self.log.append(testing.allocator, 'R') catch {};
        self.held = false;
    }
};

const App = struct { store: *Store, calls: u32 = 0 };

fn hCharge(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    try app.store.respond(ctx, 201, "text/plain", "charged");
}

fn serve(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var response_body_buf: [4096]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
    http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

test "Backend seam through the middleware: lookup, then put before release; replay without the handler" {
    var lb: LogBackend = .{};
    defer lb.deinit();
    var store = Store{ .backend = lb.backend() };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = root.Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.add(.post, "/charge", hCharge);
    const req = "POST /charge HTTP/1.1\r\nHost: x\r\nIdempotency-Key: k1\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc";
    var b1: [1024]u8 = undefined;
    const first = serve(&r, req, &b1);
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 201"));
    try testing.expectEqualStrings("LPR", lb.log.items);
    var b2: [1024]u8 = undefined;
    const second = serve(&r, req, &b2);
    try testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 201"));
    try testing.expect(std.mem.find(u8, second, "Idempotent-Replayed: true") != null);
    try testing.expect(std.mem.endsWith(u8, second, "charged"));
    try testing.expectEqual(@as(u32, 1), app.calls);
    try testing.expectEqualStrings("LPRL", lb.log.items);
}

test "KvBackend: a lease check against a clock that jumped backwards does not overflow (sweep ID-2)" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var clk: Clock = .{};
    var db = try openDb(&sim, &clk);
    defer db.close();
    var kb = KvBackend{ .db = &db, .gpa = testing.allocator };
    defer kb.deinit();
    const b = kb.backend();
    // Reserved at the far end of the clock's range, then asked again at the
    // other end: `now - since` is minInt - maxInt, which must saturate, not wrap.
    try testing.expect((try b.vtable.lookupOrReserve(b.ptr, "k", std.math.maxInt(i64), 5, testing.allocator)) == .reserved);
    try testing.expect((try b.vtable.lookupOrReserve(b.ptr, "k", std.math.minInt(i64), 5, testing.allocator)) == .in_flight);
    b.vtable.release(b.ptr, "k");
}

// ── whole-module mutation run 2026-11-07 (A1): tests for the survivors ──────

/// Whether `key` holds a live record (the record is read and released).
fn isFound(b: Backend, key: []const u8) !bool {
    switch (try b.vtable.lookupOrReserve(b.ptr, key, 0, 0, testing.allocator)) {
        .found => |v| {
            testing.allocator.free(v);
            return true;
        },
        .reserved => {
            b.vtable.release(b.ptr, key);
            return false;
        },
        .in_flight => return error.TestUnexpectedInFlight,
    }
}

test "KvBackend: deinit with a reservation still held frees its key" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var clk: Clock = .{};
    var db = try openDb(&sim, &clk);
    defer db.close();
    var kb = KvBackend{ .db = &db, .gpa = testing.allocator };
    const b = kb.backend();
    try testing.expect((try b.vtable.lookupOrReserve(b.ptr, "held", 1, 0, testing.allocator)) == .reserved);
    kb.deinit();
}

test "KvBackend: an allocation failure is an error, never a leak or a reservation left behind" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var clk: Clock = .{};
    var db = try openDb(&sim, &clk);
    defer db.close();
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    var kb = KvBackend{ .db = &db, .gpa = fa.allocator() };
    defer kb.deinit();
    const b = kb.backend();
    // The key copy succeeds, the reservation map's growth fails: the copy is freed.
    fa.fail_index = fa.alloc_index + 1;
    try testing.expectError(error.OutOfMemory, b.vtable.lookupOrReserve(b.ptr, "k1", 1, 0, testing.allocator));
    try testing.expectEqual(@as(usize, 0), kb.in_flight.count());
    fa.fail_index = std.math.maxInt(usize);
    // The record is there, reading it needs memory the caller's allocator refuses:
    // the reservation taken a moment before is released, and the error is the error.
    b.vtable.put(b.ptr, "k2", "value", 1, 0);
    var no_mem = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, b.vtable.lookupOrReserve(b.ptr, "k2", 1, 0, no_mem.allocator()));
    try testing.expectEqual(@as(usize, 0), kb.in_flight.count());
}

test "KvBackend.put: ttl 0 is no expiry; the expiry is whole ms rounded up, and age == ttl is already gone" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var clk: Clock = .{};
    var db = try openDb(&sim, &clk);
    defer db.close();
    var kb = KvBackend{ .db = &db, .gpa = testing.allocator };
    defer kb.deinit();
    const b = kb.backend();
    b.vtable.put(b.ptr, "forever", "v", 0, 0);
    b.vtable.put(b.ptr, "exact", "v", 0, 60 * std.time.ns_per_s); // 60000 ms
    b.vtable.put(b.ptr, "frac", "v", 0, 1_500_000); // 1.5 ms: 2 ms
    clk.now += 1;
    try testing.expect(try isFound(b, "frac"));
    clk.now += 1;
    try testing.expect(!try isFound(b, "frac"));
    clk.now += 59_997; // 59999 ms after the writes
    try testing.expect(try isFound(b, "exact"));
    clk.now += 1; // age == ttl
    try testing.expect(!try isFound(b, "exact"));
    clk.now += 1_000_000_000;
    try testing.expect(try isFound(b, "forever"));
}

test "KvBackend.put: a failed write is counted, not raised" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var clk: Clock = .{};
    var db = try openDb(&sim, &clk);
    defer db.close();
    var kb = KvBackend{ .db = &db, .gpa = testing.allocator };
    defer kb.deinit();
    const b = kb.backend();
    b.vtable.put(b.ptr, "ok", "v", 0, 0);
    try testing.expectEqual(@as(u64, 0), kb.write_errors);
    sim.ops_until_crash = 0; // the next storage side effect fails
    b.vtable.put(b.ptr, "lost", "v", 0, 0);
    try testing.expectEqual(@as(u64, 1), kb.write_errors);
}

test "beginBackend: an allocation failure withdraws the backend's reservation and leaks nothing" {
    var lb: LogBackend = .{};
    defer lb.deinit();
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    var b = lb.backend();
    b.gpa = fa.allocator();
    var store = Store{ .backend = b };
    defer store.deinit();
    var req: u8 = 0;
    fa.fail_index = fa.alloc_index; // the key copy
    try testing.expectError(error.OutOfMemory, store.begin("k1", digest_a, &req, testing.allocator));
    try testing.expect(!lb.held);
    fa.fail_index = fa.alloc_index + 1; // the binding's growth, after the key copy
    try testing.expectError(error.OutOfMemory, store.begin("k2", digest_a, &req, testing.allocator));
    try testing.expect(!lb.held);
    fa.fail_index = std.math.maxInt(usize);
    try testing.expect((try store.begin("k3", digest_a, &req, testing.allocator)) == .reserved);
    store.finish("k3", &req);
    try testing.expect(!lb.held);
}

test "Store.deinit frees the binding of a backend reservation still held" {
    var lb: LogBackend = .{};
    defer lb.deinit();
    var store = Store{ .backend = lb.backend() };
    var req: u8 = 0;
    try testing.expect((try store.begin("held", digest_a, &req, testing.allocator)) == .reserved);
    store.deinit();
}

test "KvBackend through begin: a digest that differs in any single byte is a mismatch" {
    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var clk: Clock = .{};
    var db = try openDb(&sim, &clk);
    defer db.close();
    var kb = KvBackend{ .db = &db, .gpa = testing.allocator };
    defer kb.deinit();
    var store = Store{ .backend = kb.backend(), .clock = clk.storeClock() };
    defer store.deinit();
    var d: [32]u8 = undefined;
    for (&d, 0..) |*c, i| c.* = @intCast(i * 5 + 2);
    try testing.expect((try store.begin("k", d, null, testing.allocator)) == .reserved);
    store.record("k", d, 200, "text/plain", "ok");
    store.finish("k", null);
    for (0..32) |i| {
        var other = d;
        other[i] ^= 0x80;
        errdefer std.debug.print("byte {d} of the digest differs\n", .{i});
        try testing.expect((try store.begin("k", other, null, testing.allocator)) == .mismatch);
    }
    switch (try store.begin("k", d, null, testing.allocator)) {
        .replay => |blob| testing.allocator.free(blob),
        else => return error.TestExpectedReplay,
    }
}
