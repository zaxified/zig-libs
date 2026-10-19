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

    // Lease: no takeover before it runs out, takeover after.
    store.lease_ns = 500;
    clk.now += 499;
    try testing.expect((try store.begin("k", digest_a, null, testing.allocator)) == .in_flight);
    clk.now += 2;
    try testing.expect((try store.begin("k", digest_a, null, testing.allocator)) == .reserved);
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
