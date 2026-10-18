// SPDX-License-Identifier: MIT

//! Where a `Manager` keeps what must outlive the process: account keys,
//! issued certificates and their keys, and — for a fleet — challenge data
//! and issuance locks. Modeled on CertMagic's `Storage` + `Locker` and
//! autocert's `Cache` (design only).
//!
//! `Storage` is a small vtable so a deployment can put it anywhere (a
//! database, a key-value service); `DirStorage` is the file-system one
//! (autocert's `DirCache`), `MemStorage` the in-process one for tests and
//! single-run tools.
//!
//! Keys (`path` parameters) are relative `/`-separated paths of `[A-Za-z0-9._@+-]` segments; no
//! empty, `.` or `..` segment (`validKey`). Values are opaque bytes; the
//! manager writes PEM.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{
    OutOfMemory,
    /// `load` of a key that is not there.
    NotFound,
    /// The key is not a valid storage key (see `validKey`).
    InvalidKey,
    /// The backend failed (I/O, permissions, a full disk, a value over the
    /// backend's size limit).
    StorageFailed,
};

/// Upper bound for one stored value; a bigger one is `StorageFailed`.
pub const max_value_len = 1 << 20;

/// Longest key accepted.
pub const max_key_len = 512;

/// The storage interface (CertMagic `Storage` + `Locker`).
pub const Storage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The value under `key`, allocated with `gpa`; `NotFound` when absent.
        load: *const fn (ptr: *anyopaque, gpa: Allocator, path: []const u8) Error![]u8,
        /// Store `value` under `key`, replacing any old value **atomically**:
        /// a reader sees the old value or the new one, never a mix, and a
        /// crash leaves one of the two.
        store: *const fn (ptr: *anyopaque, path: []const u8, value: []const u8) Error!void,
        /// Remove `key`; absent is not an error.
        delete: *const fn (ptr: *anyopaque, path: []const u8) Error!void,
        /// Store `value` under `key` only if `key` is absent, as one atomic
        /// step: false (nothing written) when a value is there. Two nodes
        /// creating the same key at once: exactly one gets true. Optional
        /// for a backend written before 2026-10-18: without it `Storage.create`
        /// is load-then-store, which two nodes can both win.
        create: ?*const fn (ptr: *anyopaque, path: []const u8, value: []const u8) Error!bool = null,
        /// Take the lock `name` for `owner` until `now + lease_s` (epoch
        /// seconds). True when taken: free, expired, or already `owner`'s (the
        /// lease is then extended). False when another owner holds an unexpired
        /// lease. Locks coordinate the nodes of a fleet that share one storage.
        tryLock: *const fn (ptr: *anyopaque, name: []const u8, owner: []const u8, now: i64, lease_s: u32) Error!bool,
        /// Release `name` if `owner` holds it; anything else is a no-op.
        unlock: *const fn (ptr: *anyopaque, name: []const u8, owner: []const u8) void,
    };

    pub fn load(s: Storage, gpa: Allocator, path: []const u8) Error![]u8 {
        if (!validKey(path)) return error.InvalidKey;
        return s.vtable.load(s.ptr, gpa, path);
    }

    pub fn store(s: Storage, path: []const u8, value: []const u8) Error!void {
        if (!validKey(path)) return error.InvalidKey;
        if (value.len > max_value_len) return error.StorageFailed;
        return s.vtable.store(s.ptr, path, value);
    }

    pub fn delete(s: Storage, path: []const u8) Error!void {
        if (!validKey(path)) return error.InvalidKey;
        return s.vtable.delete(s.ptr, path);
    }

    /// `value` under `path` only if nothing is there yet; false when a value
    /// is (see `VTable.create`). `loadOrCreateAccountKey` creates through it,
    /// so two nodes starting at once end up with one account key.
    /// `gpa` serves only a backend without `VTable.create` (its load).
    pub fn create(s: Storage, gpa: Allocator, path: []const u8, value: []const u8) Error!bool {
        if (!validKey(path)) return error.InvalidKey;
        if (value.len > max_value_len) return error.StorageFailed;
        if (s.vtable.create) |f| return f(s.ptr, path, value);
        if (s.vtable.load(s.ptr, gpa, path)) |old| {
            std.crypto.secureZero(u8, old);
            gpa.free(old);
            return false;
        } else |err| switch (err) {
            error.NotFound => {},
            else => return err,
        }
        try s.vtable.store(s.ptr, path, value);
        return true;
    }

    pub fn tryLock(s: Storage, name: []const u8, owner: []const u8, now: i64, lease_s: u32) Error!bool {
        if (!validKey(name)) return error.InvalidKey;
        if (!validOwner(owner)) return error.InvalidKey;
        return s.vtable.tryLock(s.ptr, name, owner, now, lease_s);
    }

    pub fn unlock(s: Storage, name: []const u8, owner: []const u8) void {
        if (!validKey(name) or !validOwner(owner)) return;
        s.vtable.unlock(s.ptr, name, owner);
    }
};

/// A storage key: 1..`max_key_len` bytes, `/`-separated segments of
/// `[A-Za-z0-9._@+-]`, none empty, `.` or `..`, no leading or trailing `/`.
pub fn validKey(path: []const u8) bool {
    if (path.len == 0 or path.len > max_key_len) return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0) return false;
        if (std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
        for (seg) |ch| if (!keyChar(ch)) return false;
    }
    return true;
}

fn keyChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '.' or ch == '_' or ch == '-' or ch == '@' or ch == '+';
}

/// A lock owner: 1..64 key characters (no `/`, no newline).
fn validOwner(owner: []const u8) bool {
    if (owner.len == 0 or owner.len > 64) return false;
    for (owner) |ch| if (!keyChar(ch)) return false;
    return true;
}

// ── the file-system backend ─────────────────────────────────────────────────

/// Files under one directory (autocert `DirCache`, CertMagic `FileStorage`):
/// a key is a relative path. Directories are created `0700`, files `0600`
/// (they hold private keys); every write is a fresh file fsynced and renamed
/// over the old one. Locks are files under `locks/` holding the owner and the
/// lease expiry. Every lock operation — read, decide, create, extend, take
/// over, release — runs under an exclusive `flock` of `locks/.guard`, so it is
/// one step for every process and thread using the directory: a stale lock is
/// taken over by exactly one node, and `unlock` never deletes a lock another
/// node has just taken (CertMagic's file locks, read-then-delete, can do both).
/// `flock` reaches across hosts only where the file system carries it (local
/// disks; NFS through the kernel's lock manager). Where it is refused
/// (`FileLocksUnsupported`) the operations run unguarded: a lock is still
/// created by an exclusive link, but a takeover can then be won twice — one
/// duplicate order at the CA, never a corrupted file.
pub const DirStorage = struct {
    io: std.Io,
    /// Caller-owned; open it before `init` (create it `0700`).
    dir: std.Io.Dir,

    pub fn init(io: std.Io, dir: std.Io.Dir) DirStorage {
        return .{ .io = io, .dir = dir };
    }

    pub fn storage(d: *DirStorage) Storage {
        return .{ .ptr = d, .vtable = &vtable };
    }

    const vtable: Storage.VTable = .{
        .load = dirLoad,
        .store = dirStore,
        .delete = dirDelete,
        .create = dirCreate,
        .tryLock = dirTryLock,
        .unlock = dirUnlock,
    };

    const dir_permissions: std.Io.File.Permissions = @fromBackingInt(@intCast(0o700));
    const file_permissions: std.Io.File.Permissions = @fromBackingInt(@intCast(0o600));

    fn of(ptr: *anyopaque) *DirStorage {
        return @ptrCast(@alignCast(ptr));
    }

    fn dirLoad(ptr: *anyopaque, gpa: Allocator, key: []const u8) Error![]u8 {
        const d = of(ptr);
        return d.dir.readFileAlloc(d.io, key, gpa, .limited(max_value_len + 1)) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.FileNotFound => error.NotFound,
            else => error.StorageFailed,
        };
    }

    /// Create every parent directory of `key`, `0700`.
    fn makeParents(d: *DirStorage, key: []const u8) Error!void {
        var at: usize = 0;
        while (std.mem.indexOfScalarPos(u8, key, at, '/')) |slash| : (at = slash + 1) {
            d.dir.createDir(d.io, key[0..slash], dir_permissions) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return error.StorageFailed,
            };
        }
    }

    fn dirStore(ptr: *anyopaque, key: []const u8, value: []const u8) Error!void {
        const d = of(ptr);
        try d.makeParents(key);
        var atomic = d.dir.createFileAtomic(d.io, key, .{
            .permissions = file_permissions,
            .replace = true,
        }) catch return error.StorageFailed;
        defer atomic.deinit(d.io);
        atomic.file.writeStreamingAll(d.io, value) catch return error.StorageFailed;
        // A rename of an unsynced file can surface as an empty file after a
        // crash; the value must be on disk before it replaces the old one.
        atomic.file.sync(d.io) catch return error.StorageFailed;
        atomic.replace(d.io) catch return error.StorageFailed;
    }

    fn dirDelete(ptr: *anyopaque, key: []const u8) Error!void {
        const d = of(ptr);
        d.dir.deleteFile(d.io, key) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return error.StorageFailed,
        };
    }

    const lock_dir = "locks/";
    const max_lock_path = lock_dir.len + max_key_len + ".lock".len;

    fn lockPath(buf: *[max_lock_path]u8, name: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "{s}{s}.lock", .{ lock_dir, name }) catch unreachable; // name <= max_key_len
    }

    /// Write `value` to `path` whole, fsynced, linked in only if `path` is
    /// absent; false when it exists.
    fn createExclusive(d: *DirStorage, path: []const u8, value: []const u8) Error!bool {
        try d.makeParents(path);
        var atomic = d.dir.createFileAtomic(d.io, path, .{ .permissions = file_permissions }) catch
            return error.StorageFailed;
        defer atomic.deinit(d.io);
        atomic.file.writeStreamingAll(d.io, value) catch return error.StorageFailed;
        atomic.file.sync(d.io) catch return error.StorageFailed;
        atomic.link(d.io) catch |err| switch (err) {
            error.PathAlreadyExists => return false,
            else => return error.StorageFailed,
        };
        return true;
    }

    fn dirCreate(ptr: *anyopaque, key: []const u8, value: []const u8) Error!bool {
        return of(ptr).createExclusive(key, value);
    }

    const guard_path = lock_dir ++ ".guard";

    /// The guard file, open and exclusively `flock`ed (blocks while another
    /// process or thread holds it); null where the file system has no
    /// `flock`. Close it to release.
    fn guard(d: *DirStorage) Error!?std.Io.File {
        try d.makeParents(guard_path);
        return d.dir.createFile(d.io, guard_path, .{
            .truncate = false,
            .lock = .exclusive,
            .permissions = file_permissions,
        }) catch |err| switch (err) {
            error.FileLocksUnsupported => null,
            else => error.StorageFailed,
        };
    }

    fn dirTryLock(ptr: *anyopaque, name: []const u8, owner: []const u8, now: i64, lease_s: u32) Error!bool {
        const d = of(ptr);
        var path_buf: [max_lock_path]u8 = undefined;
        const path = lockPath(&path_buf, name);
        var buf: [96]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{s}\n{d}\n", .{ owner, now +| lease_s }) catch unreachable; // owner <= 64
        const g = try d.guard();
        defer if (g) |f| f.close(d.io);
        var read_buf: [96]u8 = undefined;
        const held = d.readLock(path, &read_buf) catch |err| switch (err) {
            // Free. Created by an exclusive link, so even unguarded only one
            // of two creators wins.
            error.NotFound => return d.createExclusive(path, text),
            else => return err,
        };
        const mine = std.mem.eql(u8, held.owner, owner);
        if (!mine and held.expiry > now) return false;
        if (mine or g != null) {
            // Ours (extend the lease), or expired under the guard (take it
            // over): an atomic replace.
            try dirStore(ptr, path, text);
            return true;
        }
        // Expired, unguarded: delete, then race the others for an exclusive
        // create — usually one winner, two when one deletes the other's
        // fresh lock (the caveat above).
        try dirDelete(ptr, path);
        return d.createExclusive(path, text);
    }

    const Held = struct { owner: []const u8, expiry: i64 };

    fn readLock(d: *DirStorage, path: []const u8, buf: *[96]u8) Error!Held {
        const text = d.dir.readFile(d.io, path, buf) catch |err| switch (err) {
            error.FileNotFound => return error.NotFound,
            else => return error.StorageFailed,
        };
        // A lock we cannot read is treated as expired (owner "", expiry 0):
        // it was not written by this code, or by a crashed writer of an older
        // format, and waiting on it forever would stop renewals.
        var lines = std.mem.splitScalar(u8, text, '\n');
        const owner = lines.next() orelse "";
        const expiry = std.fmt.parseInt(i64, lines.next() orelse "", 10) catch 0;
        return .{ .owner = owner, .expiry = expiry };
    }

    fn dirUnlock(ptr: *anyopaque, name: []const u8, owner: []const u8) void {
        const d = of(ptr);
        var path_buf: [max_lock_path]u8 = undefined;
        const path = lockPath(&path_buf, name);
        const g = d.guard() catch return;
        defer if (g) |f| f.close(d.io);
        var read_buf: [96]u8 = undefined;
        const held = d.readLock(path, &read_buf) catch return;
        if (!std.mem.eql(u8, held.owner, owner)) return;
        dirDelete(ptr, path) catch {};
    }
};

// ── the in-memory backend ───────────────────────────────────────────────────

/// A thread-safe map in memory: tests, one-shot tools, and a process that
/// keeps nothing across restarts (it will re-issue on every start — mind the
/// CA's rate limits).
pub const MemStorage = struct {
    gpa: Allocator,
    lock: std.atomic.Mutex = .unlocked,
    values: std.StringHashMapUnmanaged([]u8) = .empty,
    locks: std.StringHashMapUnmanaged(LockEntry) = .empty,

    const LockEntry = struct { owner: [64]u8, owner_len: u8, expiry: i64 };

    pub fn init(gpa: Allocator) MemStorage {
        return .{ .gpa = gpa };
    }

    pub fn deinit(m: *MemStorage) void {
        var it = m.values.iterator();
        while (it.next()) |e| {
            m.gpa.free(e.key_ptr.*);
            std.crypto.secureZero(u8, e.value_ptr.*); // values include private keys
            m.gpa.free(e.value_ptr.*);
        }
        m.values.deinit(m.gpa);
        var lit = m.locks.keyIterator();
        while (lit.next()) |k| m.gpa.free(k.*);
        m.locks.deinit(m.gpa);
        m.* = undefined;
    }

    pub fn storage(m: *MemStorage) Storage {
        return .{ .ptr = m, .vtable = &vtable };
    }

    /// Number of stored values (tests).
    pub fn count(m: *MemStorage) usize {
        lockSpin(&m.lock);
        defer m.lock.unlock();
        return m.values.count();
    }

    const vtable: Storage.VTable = .{
        .load = memLoad,
        .store = memStore,
        .delete = memDelete,
        .create = memCreate,
        .tryLock = memTryLock,
        .unlock = memUnlock,
    };

    fn of(ptr: *anyopaque) *MemStorage {
        return @ptrCast(@alignCast(ptr));
    }

    fn memLoad(ptr: *anyopaque, gpa: Allocator, key: []const u8) Error![]u8 {
        const m = of(ptr);
        lockSpin(&m.lock);
        defer m.lock.unlock();
        const v = m.values.get(key) orelse return error.NotFound;
        return gpa.dupe(u8, v);
    }

    fn memStore(ptr: *anyopaque, key: []const u8, value: []const u8) Error!void {
        const m = of(ptr);
        const copy = try m.gpa.dupe(u8, value);
        errdefer m.gpa.free(copy);
        lockSpin(&m.lock);
        defer m.lock.unlock();
        const gop = try m.values.getOrPut(m.gpa, key);
        if (gop.found_existing) {
            std.crypto.secureZero(u8, gop.value_ptr.*);
            m.gpa.free(gop.value_ptr.*);
        } else {
            gop.key_ptr.* = m.gpa.dupe(u8, key) catch |err| {
                _ = m.values.remove(key);
                return err;
            };
        }
        gop.value_ptr.* = copy;
    }

    fn memCreate(ptr: *anyopaque, key: []const u8, value: []const u8) Error!bool {
        const m = of(ptr);
        lockSpin(&m.lock);
        defer m.lock.unlock();
        if (m.values.contains(key)) return false;
        const copy = try m.gpa.dupe(u8, value);
        errdefer {
            std.crypto.secureZero(u8, copy);
            m.gpa.free(copy);
        }
        const owned_key = try m.gpa.dupe(u8, key);
        errdefer m.gpa.free(owned_key);
        try m.values.put(m.gpa, owned_key, copy);
        return true;
    }

    fn memDelete(ptr: *anyopaque, key: []const u8) Error!void {
        const m = of(ptr);
        lockSpin(&m.lock);
        const kv = m.values.fetchRemove(key);
        m.lock.unlock();
        if (kv) |e| {
            m.gpa.free(e.key);
            std.crypto.secureZero(u8, e.value);
            m.gpa.free(e.value);
        }
    }

    fn memTryLock(ptr: *anyopaque, name: []const u8, owner: []const u8, now: i64, lease_s: u32) Error!bool {
        const m = of(ptr);
        lockSpin(&m.lock);
        defer m.lock.unlock();
        const gop = try m.locks.getOrPut(m.gpa, name);
        if (gop.found_existing) {
            const e = gop.value_ptr;
            const mine = std.mem.eql(u8, e.owner[0..e.owner_len], owner);
            if (!mine and e.expiry > now) return false;
        } else {
            gop.key_ptr.* = m.gpa.dupe(u8, name) catch |err| {
                _ = m.locks.remove(name);
                return err;
            };
        }
        var e: LockEntry = .{ .owner = undefined, .owner_len = @intCast(owner.len), .expiry = now +| lease_s };
        @memcpy(e.owner[0..owner.len], owner);
        gop.value_ptr.* = e;
        return true;
    }

    fn memUnlock(ptr: *anyopaque, name: []const u8, owner: []const u8) void {
        const m = of(ptr);
        lockSpin(&m.lock);
        defer m.lock.unlock();
        const e = m.locks.getPtr(name) orelse return;
        if (!std.mem.eql(u8, e.owner[0..e.owner_len], owner)) return;
        const kv = m.locks.fetchRemove(name).?;
        m.gpa.free(kv.key);
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "validKey: segments, characters, traversal" {
    try testing.expect(validKey("certificates/example.org.crt"));
    try testing.expect(validKey("accounts/acme-v02.api.letsencrypt.org-directory/account.key"));
    try testing.expect(validKey("a"));
    try testing.expect(!validKey(""));
    try testing.expect(!validKey("/abs"));
    try testing.expect(!validKey("trailing/"));
    try testing.expect(!validKey("a//b"));
    try testing.expect(!validKey("../etc/passwd"));
    try testing.expect(!validKey("a/../b"));
    try testing.expect(!validKey("a/./b"));
    try testing.expect(!validKey("star*"));
    try testing.expect(!validKey("sp ace"));
    try testing.expect(!validKey("nl\n"));
    try testing.expect(!validKey("back\\slash"));
    try testing.expect(!validKey(strRepeat("x", max_key_len + 1)));
}

// ── audit 2026-10-18: tests asked for by mutation survivors ─────────────────

test "validKey: the length limit is inclusive; '@' and '+' are key characters" {
    try testing.expect(validKey(strRepeat("x", max_key_len)));
    try testing.expect(!validKey(strRepeat("x", max_key_len + 1)));
    try testing.expect(validKey("a@b+c/d_e"));
}

test "Storage: lock owners are 1..64 key characters; the value limit is inclusive" {
    var mem = MemStorage.init(testing.allocator);
    defer mem.deinit();
    const s = mem.storage();
    try testing.expectError(error.InvalidKey, s.tryLock("k", "", 0, 10));
    try testing.expect(try s.tryLock("k", strRepeat("o", 64), 0, 10));
    try testing.expectError(error.InvalidKey, s.tryLock("k2", strRepeat("o", 65), 0, 10));
    try testing.expectError(error.InvalidKey, s.tryLock("k3", "bad owner", 0, 10));

    const big = try testing.allocator.alloc(u8, max_value_len + 1);
    defer testing.allocator.free(big);
    @memset(big, 'v');
    try s.store("big", big[0..max_value_len]); // exactly the limit
    try testing.expectError(error.StorageFailed, s.store("big2", big));
    try testing.expectError(error.StorageFailed, s.create(testing.allocator, "big3", big));
    try testing.expect(try s.create(testing.allocator, "big4", big[0..max_value_len]));
}

/// The contract every backend must keep — run against each.
fn checkContract(s: Storage) !void {
    const gpa = testing.allocator;
    try testing.expectError(error.NotFound, s.load(gpa, "k/v"));
    try s.store("k/v", "one");
    {
        const v = try s.load(gpa, "k/v");
        defer gpa.free(v);
        try testing.expectEqualStrings("one", v);
    }
    try s.store("k/v", "two"); // replace
    {
        const v = try s.load(gpa, "k/v");
        defer gpa.free(v);
        try testing.expectEqualStrings("two", v);
    }
    try s.delete("k/v");
    try s.delete("k/v"); // absent is fine
    try testing.expectError(error.NotFound, s.load(gpa, "k/v"));
    try testing.expectError(error.InvalidKey, s.store("../x", "v"));
    try testing.expectError(error.InvalidKey, s.load(gpa, "a//b"));

    // create: only when absent, never replaces.
    try testing.expect(try s.create(gpa, "k/new", "first"));
    try testing.expect(!try s.create(gpa, "k/new", "second"));
    {
        const v = try s.load(gpa, "k/new");
        defer gpa.free(v);
        try testing.expectEqualStrings("first", v);
    }
    try s.delete("k/new");
    try testing.expect(try s.create(gpa, "k/new", "third"));
    try s.delete("k/new");
    try testing.expectError(error.InvalidKey, s.create(gpa, "../x", "v"));

    // Locks: exclusive per owner until expiry, re-entrant (extends), released.
    try testing.expect(try s.tryLock("issue/example.org", "node-a", 1000, 60));
    try testing.expect(!try s.tryLock("issue/example.org", "node-b", 1059, 60));
    try testing.expect(try s.tryLock("issue/example.org", "node-a", 1050, 60)); // extend to 1110
    try testing.expect(!try s.tryLock("issue/example.org", "node-b", 1100, 60));
    try testing.expect(try s.tryLock("issue/example.org", "node-b", 1110, 60)); // expired → taken over
    s.unlock("issue/example.org", "node-a"); // not the holder: no-op
    try testing.expect(!try s.tryLock("issue/example.org", "node-a", 1111, 60));
    s.unlock("issue/example.org", "node-b");
    try testing.expect(try s.tryLock("issue/example.org", "node-a", 1112, 60));
    s.unlock("issue/example.org", "node-a");
    try testing.expectError(error.InvalidKey, s.tryLock("x", "bad owner", 0, 1));
}

test "MemStorage: contract" {
    var m = MemStorage.init(testing.allocator);
    defer m.deinit();
    try checkContract(m.storage());
}

test "DirStorage: contract, 0600 files in 0700 directories, no temp files left" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var d = DirStorage.init(io, tmp.dir);
    try checkContract(d.storage());

    const s = d.storage();
    s.unlock(strRepeat("x", 600), "owner"); // an invalid name is a no-op, not a path buffer overflow
    try s.store("certificates/deep/example.org.key", "secret");
    const file_stat = try tmp.dir.statFile(io, "certificates/deep/example.org.key", .{});
    try testing.expectEqual(@as(u32, 0o600), @as(u32, @backingInt(file_stat.permissions)) & 0o777);
    const dir_stat = try tmp.dir.statFile(io, "certificates/deep", .{});
    try testing.expectEqual(@as(u32, 0o700), @as(u32, @backingInt(dir_stat.permissions)) & 0o777);

    // Only the value file is in the directory: the atomic write left no temp.
    var sub = try tmp.dir.openDir(io, "certificates/deep", .{ .iterate = true });
    defer sub.close(io);
    var it = sub.iterate();
    var names: usize = 0;
    while (try it.next(io)) |e| {
        names += 1;
        try testing.expectEqualStrings("example.org.key", e.name);
    }
    try testing.expectEqual(@as(usize, 1), names);

    // A lock file this code did not write counts as expired.
    tmp.dir.createDir(io, "locks", .default_dir) catch {};
    try tmp.dir.writeFile(io, .{ .sub_path = "locks/garbled.lock", .data = "\x00\x01" });
    try testing.expect(try s.tryLock("garbled", "node-a", 5, 10));
    s.unlock("garbled", "node-a");
}

// Eight threads, each with its own open of the directory as a node of a
// fleet would have, race for the same expired lock at the same instant:
// exactly one may win each round (audit L6, 2026-10-18 — before the guard a
// takeover was read → delete → create, and two nodes could both delete the
// stale lock, the second deleting the first's fresh one, and both win).
test "DirStorage: a stale lock is taken over by exactly one of racing nodes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const nodes = 8;
    const Node = struct {
        d: DirStorage,
        name: [16]u8 = undefined,
        won: bool = false,
        failed: bool = false,
        go: *std.atomic.Value(bool),

        fn run(n: *@This()) void {
            while (!n.go.load(.acquire)) std.atomic.spinLoopHint();
            const owner = std.fmt.bufPrint(&n.name, "node-{x}", .{@intFromPtr(n) & 0xffff}) catch unreachable;
            n.won = n.d.storage().tryLock("issue/race", owner, 2000, 60) catch {
                n.failed = true;
                return;
            };
        }
    };
    var dirs: [nodes]std.Io.Dir = undefined;
    for (&dirs) |*dd| dd.* = try tmp.dir.openDir(io, ".", .{});
    defer for (dirs) |dd| dd.close(io);

    var wins_total: usize = 0;
    for (0..40) |round| {
        // A lock of a crashed node, long expired.
        var planter = DirStorage.init(io, tmp.dir);
        try planter.storage().store("locks/issue/race.lock", "node-dead\n1000\n");
        var go: std.atomic.Value(bool) = .init(false);
        var ns: [nodes]Node = undefined;
        var ts: [nodes]std.Thread = undefined;
        for (&ns, &ts, dirs) |*n, *t, dd| {
            n.* = .{ .d = DirStorage.init(io, dd), .go = &go };
            t.* = try std.Thread.spawn(.{}, Node.run, .{n});
        }
        go.store(true, .release);
        for (ts) |t| t.join();
        var wins: usize = 0;
        for (ns) |n| {
            try testing.expect(!n.failed);
            if (n.won) wins += 1;
        }
        if (wins != 1) std.debug.print("round {d}: {d} winners\n", .{ round, wins });
        try testing.expectEqual(@as(usize, 1), wins);
        wins_total += wins;
    }
    try testing.expectEqual(@as(usize, 40), wins_total);
}

// The guard is what makes a lock operation one step (L6): while another
// open of `locks/.guard` holds its `flock`, `tryLock` and `unlock` wait.
// The race test above cannot show this — its window is too narrow to be hit
// without the guard — so this one holds the guard by hand.
test "DirStorage: lock operations wait for the guard" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    tmp.dir.createDir(io, "locks", .default_dir) catch {};
    const held = try tmp.dir.createFile(io, DirStorage.guard_path, .{ .truncate = false, .lock = .exclusive });
    const Locker = struct {
        d: DirStorage,
        done: std.atomic.Value(bool) = .init(false),
        won: bool = false,
        fn run(l: *@This()) void {
            l.won = l.d.storage().tryLock("issue/g", "node-a", 10, 60) catch false;
            l.done.store(true, .release);
        }
    };
    var l: Locker = .{ .d = DirStorage.init(io, tmp.dir) };
    const t = try std.Thread.spawn(.{}, Locker.run, .{&l});
    try io.sleep(.fromMilliseconds(100), .awake);
    const finished_while_held = l.done.load(.acquire);
    held.close(io); // releases the flock
    t.join();
    try testing.expect(!finished_while_held);
    try testing.expect(l.won);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * 2 + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
