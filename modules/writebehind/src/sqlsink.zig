// SPDX-License-Identifier: MIT

//! `SqlSink`: a `Sink` over a SQL table of `(key, value)` rows, the DL6
//! adapter the `Sink` vtable was made for. It speaks SQL text through a small
//! `Executor` the caller implements over their driver (a connection, or a pool
//! checked out per call), so the module takes no database dependency and no
//! network: the statements, the dialects and the transaction shape are here,
//! the wire is the driver's.
//!
//! The statements (identifiers are validated and quoted at `init`; keys and
//! values travel as bound **binary parameters**, never spliced into the text):
//!
//!   write   postgres / sqlite  `INSERT INTO "t" ("k", "v") VALUES ($1, $2)
//!                               ON CONFLICT ("k") DO UPDATE SET "v" = excluded."v"`
//!           mysql              `INSERT INTO `t` (`k`, `v`) VALUES (?, ?)
//!                               ON DUPLICATE KEY UPDATE `v` = VALUES(`v`)`
//!   delete  `DELETE FROM "t" WHERE "k" = $1`
//!   read    `SELECT "v" FROM "t" WHERE "k" = $1`
//!
//! `write_batch` runs its operations inside one `begin` / `commit` (a
//! `rollback` on the first failure), so `Options.batch_size` turns N commits
//! into one. The table is the caller's: create it with the key column as the
//! primary key (or a unique index) and a binary value column (`bytea`,
//! `BLOB`, `BLOB`).
//!
//! Verified against a recording `Executor` only (the tests below); no live
//! database was available, so the statements are the documented upsert forms
//! of each dialect, not something this repository has run against one.

const std = @import("std");
const root = @import("root.zig");
const kvtree = @import("kvtree");

const Allocator = std.mem.Allocator;
const Sink = root.Sink;

pub const Dialect = enum { postgres, sqlite, mysql };

/// The caller's database handle. Every call may be made from a pool worker;
/// `SqlSink` serializes them (one statement or one transaction at a time), so
/// an executor over a single connection needs no lock of its own. A pooled
/// executor that checks a connection out per call must keep `begin` ..
/// `commit` on one connection, which serialization makes straightforward
/// (one transaction is open at a time).
pub const Executor = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Run `sql` with the binary `params` bound in order ($1/$2 or ?).
        exec: *const fn (ptr: *anyopaque, sql: []const u8, params: []const []const u8) anyerror!void,
        /// Run a query that yields at most one row and return its first
        /// column as bytes allocated with `gpa`; null = no row.
        query_value: *const fn (ptr: *anyopaque, gpa: Allocator, sql: []const u8, params: []const []const u8) anyerror!?[]u8,
        begin: *const fn (ptr: *anyopaque) anyerror!void,
        commit: *const fn (ptr: *anyopaque) anyerror!void,
        rollback: *const fn (ptr: *anyopaque) anyerror!void,
    };
};

pub const Config = struct {
    /// Table name, optionally schema-qualified (`schema.table`).
    table: []const u8,
    key_column: []const u8 = "k",
    value_column: []const u8 = "v",
    dialect: Dialect = .postgres,
};

pub const InitError = error{ InvalidIdentifier, OutOfMemory };

pub const SqlSink = struct {
    gpa: Allocator,
    exec: Executor,
    /// Statement texts, built once; public so a driver can prepare them.
    write_sql: []u8,
    delete_sql: []u8,
    read_sql: []u8,
    /// One statement or transaction at a time (the executor may be one
    /// connection). `io` makes a waiting flush task yield; null spins.
    lock: kvtree.Lock,

    pub fn init(gpa: Allocator, executor: Executor, cfg: Config, io: ?std.Io) InitError!SqlSink {
        const q = cfg.dialect;
        const table = try quoteQualified(gpa, q, cfg.table);
        defer gpa.free(table);
        const k = try quoteIdent(gpa, q, cfg.key_column);
        defer gpa.free(k);
        const v = try quoteIdent(gpa, q, cfg.value_column);
        defer gpa.free(v);
        const p1: []const u8 = if (q == .postgres) "$1" else "?";
        const p2: []const u8 = if (q == .postgres) "$2" else "?";
        const write_sql = switch (q) {
            .postgres, .sqlite => try std.fmt.allocPrint(gpa, "INSERT INTO {s} ({s}, {s}) VALUES ({s}, {s}) ON CONFLICT ({s}) DO UPDATE SET {s} = excluded.{s}", .{ table, k, v, p1, p2, k, v, v }),
            .mysql => try std.fmt.allocPrint(gpa, "INSERT INTO {s} ({s}, {s}) VALUES ({s}, {s}) ON DUPLICATE KEY UPDATE {s} = VALUES({s})", .{ table, k, v, p1, p2, v, v }),
        };
        errdefer gpa.free(write_sql);
        const delete_sql = try std.fmt.allocPrint(gpa, "DELETE FROM {s} WHERE {s} = {s}", .{ table, k, p1 });
        errdefer gpa.free(delete_sql);
        const read_sql = try std.fmt.allocPrint(gpa, "SELECT {s} FROM {s} WHERE {s} = {s}", .{ v, table, k, p1 });
        return .{ .gpa = gpa, .exec = executor, .write_sql = write_sql, .delete_sql = delete_sql, .read_sql = read_sql, .lock = .{ .io = io } };
    }

    pub fn deinit(self: *SqlSink) void {
        self.gpa.free(self.write_sql);
        self.gpa.free(self.delete_sql);
        self.gpa.free(self.read_sql);
    }

    pub fn sink(self: *SqlSink) Sink {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Sink.VTable{ .write = vWrite, .delete = vDelete, .read = vRead, .write_batch = vBatch };

    fn cast(ptr: *anyopaque) *SqlSink {
        return @ptrCast(@alignCast(ptr));
    }

    fn vWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self = cast(ptr);
        self.lock.acquire();
        defer self.lock.release();
        try self.exec.vtable.exec(self.exec.ptr, self.write_sql, &.{ key, value });
    }

    fn vDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self = cast(ptr);
        self.lock.acquire();
        defer self.lock.release();
        try self.exec.vtable.exec(self.exec.ptr, self.delete_sql, &.{key});
    }

    fn vRead(ptr: *anyopaque, gpa: Allocator, key: []const u8) anyerror!?[]u8 {
        const self = cast(ptr);
        self.lock.acquire();
        defer self.lock.release();
        return self.exec.vtable.query_value(self.exec.ptr, gpa, self.read_sql, &.{key});
    }

    fn vBatch(ptr: *anyopaque, ops: []const Sink.BatchOp) anyerror!void {
        const self = cast(ptr);
        self.lock.acquire();
        defer self.lock.release();
        const vt = self.exec.vtable;
        try vt.begin(self.exec.ptr);
        for (ops) |op| {
            const res = switch (op.kind) {
                .put => vt.exec(self.exec.ptr, self.write_sql, &.{ op.key, op.value }),
                .del => vt.exec(self.exec.ptr, self.delete_sql, &.{op.key}),
            };
            res catch |e| {
                vt.rollback(self.exec.ptr) catch {};
                return e;
            };
        }
        try vt.commit(self.exec.ptr);
    }
};

/// `[A-Za-z_][A-Za-z0-9_$]*`, at most 63 bytes (PostgreSQL's limit, MySQL's 64).
fn validIdent(s: []const u8) bool {
    if (s.len == 0 or s.len > 63) return false;
    if (!(std.ascii.isAlphabetic(s[0]) or s[0] == '_')) return false;
    for (s[1..]) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '$')) return false;
    return true;
}

fn quoteIdent(gpa: Allocator, d: Dialect, s: []const u8) InitError![]u8 {
    if (!validIdent(s)) return error.InvalidIdentifier;
    const q: u8 = if (d == .mysql) '`' else '"';
    return std.fmt.allocPrint(gpa, "{c}{s}{c}", .{ q, s, q });
}

/// `schema.table` (one dot) or `table`, each part quoted.
fn quoteQualified(gpa: Allocator, d: Dialect, s: []const u8) InitError![]u8 {
    if (std.mem.findScalar(u8, s, '.')) |dot| {
        const a = try quoteIdent(gpa, d, s[0..dot]);
        defer gpa.free(a);
        const b = try quoteIdent(gpa, d, s[dot + 1 ..]);
        defer gpa.free(b);
        return std.fmt.allocPrint(gpa, "{s}.{s}", .{ a, b });
    }
    return quoteIdent(gpa, d, s);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A recording executor over an in-memory table: it recognises the sink's own
/// statements (by text) and applies them, so the sink is driven end to end
/// without a database. Transactions are real enough to test: rolled-back
/// statements are undone.
const FakeDb = struct {
    gpa: Allocator,
    sink: ?*const SqlSink = null,
    rows: std.StringHashMapUnmanaged([]u8) = .empty,
    snapshot: ?std.StringHashMapUnmanaged([]u8) = null,
    log: std.ArrayList([]const u8) = .empty,
    commits: usize = 0,
    rollbacks: usize = 0,
    in_tx: bool = false,
    fail_key: ?[]const u8 = null,

    fn deinit(self: *FakeDb) void {
        self.clear(&self.rows);
        if (self.snapshot) |*s| self.clear(s);
        for (self.log.items) |l| self.gpa.free(l);
        self.log.deinit(self.gpa);
    }
    fn clear(self: *FakeDb, m: *std.StringHashMapUnmanaged([]u8)) void {
        var it = m.iterator();
        while (it.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            self.gpa.free(e.value_ptr.*);
        }
        m.deinit(self.gpa);
    }
    fn copy(self: *FakeDb, m: *const std.StringHashMapUnmanaged([]u8)) !std.StringHashMapUnmanaged([]u8) {
        var out: std.StringHashMapUnmanaged([]u8) = .empty;
        var it = m.iterator();
        while (it.next()) |e| try out.put(self.gpa, try self.gpa.dupe(u8, e.key_ptr.*), try self.gpa.dupe(u8, e.value_ptr.*));
        return out;
    }
    fn exec(ptr: *anyopaque, sql: []const u8, params: []const []const u8) anyerror!void {
        const self: *FakeDb = @ptrCast(@alignCast(ptr));
        try self.log.append(self.gpa, try self.gpa.dupe(u8, sql));
        if (self.fail_key) |fk| if (std.mem.eql(u8, params[0], fk)) return error.ConstraintViolation;
        const s = self.sink.?;
        if (std.mem.eql(u8, sql, s.write_sql)) {
            try testing.expectEqual(@as(usize, 2), params.len);
            const v = try self.gpa.dupe(u8, params[1]);
            if (self.rows.getPtr(params[0])) |slot| {
                self.gpa.free(slot.*);
                slot.* = v;
            } else try self.rows.put(self.gpa, try self.gpa.dupe(u8, params[0]), v);
        } else if (std.mem.eql(u8, sql, s.delete_sql)) {
            try testing.expectEqual(@as(usize, 1), params.len);
            if (self.rows.fetchRemove(params[0])) |kv| {
                self.gpa.free(kv.key);
                self.gpa.free(kv.value);
            }
        } else return error.UnknownStatement;
    }
    fn query(ptr: *anyopaque, gpa: Allocator, sql: []const u8, params: []const []const u8) anyerror!?[]u8 {
        const self: *FakeDb = @ptrCast(@alignCast(ptr));
        try testing.expectEqualStrings(self.sink.?.read_sql, sql);
        const v = self.rows.get(params[0]) orelse return null;
        return try gpa.dupe(u8, v);
    }
    fn begin(ptr: *anyopaque) anyerror!void {
        const self: *FakeDb = @ptrCast(@alignCast(ptr));
        try testing.expect(!self.in_tx);
        self.in_tx = true;
        self.snapshot = try self.copy(&self.rows);
    }
    fn commit(ptr: *anyopaque) anyerror!void {
        const self: *FakeDb = @ptrCast(@alignCast(ptr));
        try testing.expect(self.in_tx);
        self.in_tx = false;
        self.commits += 1;
        self.clear(&self.snapshot.?);
        self.snapshot = null;
    }
    fn rollback(ptr: *anyopaque) anyerror!void {
        const self: *FakeDb = @ptrCast(@alignCast(ptr));
        try testing.expect(self.in_tx);
        self.in_tx = false;
        self.rollbacks += 1;
        self.clear(&self.rows);
        self.rows = self.snapshot.?;
        self.snapshot = null;
    }
    const vt = Executor.VTable{ .exec = exec, .query_value = query, .begin = begin, .commit = commit, .rollback = rollback };
    fn executor(self: *FakeDb) Executor {
        return .{ .ptr = self, .vtable = &vt };
    }
};

test "SqlSink: statements per dialect, identifiers validated and quoted" {
    var db: FakeDb = .{ .gpa = testing.allocator };
    defer db.deinit();
    var pg = try SqlSink.init(testing.allocator, db.executor(), .{ .table = "app.cache_rows", .key_column = "ck", .value_column = "cv" }, null);
    defer pg.deinit();
    try testing.expectEqualStrings("INSERT INTO \"app\".\"cache_rows\" (\"ck\", \"cv\") VALUES ($1, $2) ON CONFLICT (\"ck\") DO UPDATE SET \"cv\" = excluded.\"cv\"", pg.write_sql);
    try testing.expectEqualStrings("DELETE FROM \"app\".\"cache_rows\" WHERE \"ck\" = $1", pg.delete_sql);
    try testing.expectEqualStrings("SELECT \"cv\" FROM \"app\".\"cache_rows\" WHERE \"ck\" = $1", pg.read_sql);
    var lite = try SqlSink.init(testing.allocator, db.executor(), .{ .table = "t", .dialect = .sqlite }, null);
    defer lite.deinit();
    try testing.expectEqualStrings("INSERT INTO \"t\" (\"k\", \"v\") VALUES (?, ?) ON CONFLICT (\"k\") DO UPDATE SET \"v\" = excluded.\"v\"", lite.write_sql);
    var my = try SqlSink.init(testing.allocator, db.executor(), .{ .table = "t", .dialect = .mysql }, null);
    defer my.deinit();
    try testing.expectEqualStrings("INSERT INTO `t` (`k`, `v`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `v` = VALUES(`v`)", my.write_sql);
    try testing.expectEqualStrings("SELECT `v` FROM `t` WHERE `k` = ?", my.read_sql);

    const long_ident: [64]u8 = @splat('x');
    for ([_][]const u8{ "", "1t", "a b", "a\"b", "t;DROP TABLE x", "a.b.c", ".t", "t.", &long_ident }) |bad| {
        try testing.expectError(error.InvalidIdentifier, SqlSink.init(testing.allocator, db.executor(), .{ .table = bad }, null));
    }
    try testing.expectError(error.InvalidIdentifier, SqlSink.init(testing.allocator, db.executor(), .{ .table = "t", .key_column = "k\"" }, null));
    try testing.expectError(error.InvalidIdentifier, SqlSink.init(testing.allocator, db.executor(), .{ .table = "t", .value_column = "v) --" }, null));
}

test "SqlSink: write, overwrite, delete, read; binary keys and values travel as parameters" {
    var db: FakeDb = .{ .gpa = testing.allocator };
    defer db.deinit();
    var s = try SqlSink.init(testing.allocator, db.executor(), .{ .table = "t" }, null);
    defer s.deinit();
    db.sink = &s;
    const sk = s.sink();
    try testing.expect(sk.canRead() and sk.canBatch());
    const key = "k'; DROP TABLE t; --\x00\xff";
    const val = "v\x00\x01\xfe";
    try sk.write(key, val);
    try sk.write(key, "second");
    const got = (try sk.read(testing.allocator, key)).?;
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("second", got);
    try sk.delete(key);
    try testing.expect((try sk.read(testing.allocator, key)) == null);
    try sk.delete(key); // absent: fine
    for (db.log.items) |l| try testing.expect(std.mem.find(u8, l, "DROP") == null); // the text never carries data
}

test "SqlSink: write_batch is one transaction, rolled back whole on a failure" {
    var db: FakeDb = .{ .gpa = testing.allocator };
    defer db.deinit();
    var s = try SqlSink.init(testing.allocator, db.executor(), .{ .table = "t" }, null);
    defer s.deinit();
    db.sink = &s;
    const sk = s.sink();
    try sk.write("old", "1");
    try sk.writeBatch(&.{
        .{ .kind = .put, .key = "a", .value = "1" },
        .{ .kind = .put, .key = "b", .value = "2" },
        .{ .kind = .del, .key = "old", .value = "" },
    });
    try testing.expectEqual(@as(usize, 1), db.commits);
    try testing.expectEqual(@as(usize, 2), db.rows.count());
    try testing.expect(db.rows.get("old") == null);

    db.fail_key = "bad";
    try testing.expectError(error.ConstraintViolation, sk.writeBatch(&.{
        .{ .kind = .put, .key = "c", .value = "3" },
        .{ .kind = .put, .key = "bad", .value = "x" },
    }));
    try testing.expectEqual(@as(usize, 1), db.rollbacks);
    try testing.expectEqual(@as(usize, 1), db.commits);
    try testing.expect(db.rows.get("c") == null); // undone with the rest
    try testing.expectEqual(@as(usize, 2), db.rows.count());
}

test "SqlSink under a Coordinator: batched write-behind lands in the table in one commit per batch" {
    var db: FakeDb = .{ .gpa = testing.allocator };
    defer db.deinit();
    var s = try SqlSink.init(testing.allocator, db.executor(), .{ .table = "t" }, null);
    defer s.deinit();
    db.sink = &s;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var wal_sim = root.SimStorage.init(testing.allocator);
    defer wal_sim.deinit();
    const c = try root.Coordinator.init(testing.allocator, .{
        .io = threaded.io(),
        .sink = s.sink(),
        .wal_store = wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 256,
        .n_workers = 1,
        .batch_size = 5,
        .coalesce_writes = true,
    });
    defer c.deinit();
    var kb: [8]u8 = undefined;
    for (0..20) |i| {
        const k = std.fmt.bufPrint(&kb, "k{d}", .{i % 10}) catch unreachable;
        try c.put(k, k);
    }
    try c.flushAll();
    try testing.expectEqual(@as(usize, 10), db.rows.count());
    try testing.expect(db.commits >= 2 and db.commits <= 10);
    try testing.expectEqual(@as(usize, 0), db.rollbacks);
}
