// SPDX-License-Identifier: MIT

//! Heap secrets are wiped BEFORE they are freed (mutation run 2026-11-06).
//!
//! `std.testing.allocator` poisons freed memory, so a missing `secureZero`
//! before a `free` is invisible to a test that reads the buffer afterwards.
//! `Spy` looks at the block at the moment it is freed instead: every block of
//! the watched length must be all zero then. A secret PEM of a distinctive
//! length (37 or 41 octets here) cannot be mistaken for another allocation of
//! the module under test.

const std = @import("std");
const builtin = @import("builtin");
const acme = @import("root.zig");

const testing = std.testing;

/// `Allocator.free` poisons a block (`@memset(.., undefined)`) before the backend
/// sees it in Debug and ReleaseSafe, so a wipe is visible to `Spy` in the
/// optimized modes only (the stack probes skip the same way).
fn needsOptimized() !void {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
}

/// Passes through to `child`; on every `free` of a block of `watch_len` bytes
/// it records whether the bytes were all zero. `fail_at` makes that `alloc`
/// call (0-based) fail.
pub const Spy = struct {
    child: std.mem.Allocator,
    watch_len: usize,
    fail_at: usize = std.math.maxInt(usize),
    allocs: usize = 0,
    zero_frees: usize = 0,
    dirty_frees: usize = 0,

    pub fn allocator(s: *Spy) std.mem.Allocator {
        return .{ .ptr = s, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const s: *Spy = @ptrCast(@alignCast(ctx));
        const k = s.allocs;
        s.allocs += 1;
        if (k == s.fail_at) return null;
        return s.child.rawAlloc(len, alignment, ra);
    }

    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const s: *Spy = @ptrCast(@alignCast(ctx));
        if (memory.len == s.watch_len) {
            if (std.mem.allEqual(u8, memory, 0)) s.zero_frees += 1 else s.dirty_frees += 1;
        }
        s.child.rawFree(memory, alignment, ra);
    }
};

test "TlsAlpnResponder: the validation key is wiped before each free of a copy of it" {
    try needsOptimized();
    const key: [37]u8 = @splat('K');
    var spy: Spy = .{ .child = testing.allocator, .watch_len = key.len };
    {
        var r = acme.TlsAlpnResponder.init(spy.allocator());
        defer r.deinit();
        try r.set("a.example", "CERT", &key);
        try r.set("a.example", "CERT2", &key); // replaces: the old copy goes
        try testing.expectEqual(@as(usize, 1), spy.zero_frees);

        var mat = (try r.getMaterial(spy.allocator(), "a.example")).?; // the caller's copy
        mat.deinit(spy.allocator());
        try testing.expectEqual(@as(usize, 2), spy.zero_frees);

        r.remove("a.example");
        try testing.expectEqual(@as(usize, 3), spy.zero_frees);

        try r.set("b.example", "CERT", &key);
    } // deinit
    try testing.expectEqual(@as(usize, 4), spy.zero_frees);
    try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
}

test "TlsAlpnResponder.set: when the map cannot grow, the key copy is wiped before it is freed" {
    try needsOptimized();
    const key: [37]u8 = @splat('K');
    // alloc 0: the certificate copy, 1: the key copy, 2: the map.
    var spy: Spy = .{ .child = testing.allocator, .watch_len = key.len, .fail_at = 2 };
    var r = acme.TlsAlpnResponder.init(spy.allocator());
    defer r.deinit();
    try testing.expectError(error.OutOfMemory, r.set("a.example", "CERT", &key));
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
}

test "Manager.Material.deinit wipes the key before freeing it" {
    try needsOptimized();
    const key: [37]u8 = @splat('K');
    var spy: Spy = .{ .child = testing.allocator, .watch_len = key.len };
    const a = spy.allocator();
    var mt: acme.Manager.Material = .{ .chain_pem = try a.dupe(u8, "chain"), .key_pem = try a.dupe(u8, &key), .not_after = 1 };
    mt.deinit(a);
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
}

test "MemStorage: a value is wiped when it is replaced, deleted, and when the storage goes" {
    try needsOptimized();
    const v: [41]u8 = @splat('V');
    var spy: Spy = .{ .child = testing.allocator, .watch_len = v.len };
    {
        var ms = acme.storage.MemStorage.init(spy.allocator());
        defer ms.deinit();
        const s = ms.storage();
        try s.store("a", &v);
        try s.store("a", &v); // replaces: the old copy goes
        try testing.expectEqual(@as(usize, 1), spy.zero_frees);
        try s.delete("a");
        try testing.expectEqual(@as(usize, 2), spy.zero_frees);
        try s.store("b", &v);
        try testing.expect(!(try s.create(spy.allocator(), "b", &v))); // taken: nothing copied
        try testing.expectEqual(@as(usize, 2), spy.zero_frees);
    } // deinit
    try testing.expectEqual(@as(usize, 3), spy.zero_frees);
    try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
}

test "MemStorage.create: when the key cannot be copied, the value copy is wiped before it is freed" {
    try needsOptimized();
    const v: [41]u8 = @splat('V');
    // alloc 0: the value copy, 1: the key copy.
    var spy: Spy = .{ .child = testing.allocator, .watch_len = v.len, .fail_at = 1 };
    var ms = acme.storage.MemStorage.init(spy.allocator());
    defer ms.deinit();
    try testing.expectError(error.OutOfMemory, ms.storage().create(testing.allocator, "k", &v));
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
}

const NoCreate = struct {
    var dummy: u8 = 0;

    fn load(_: *anyopaque, gpa: std.mem.Allocator, _: []const u8) acme.storage.Error![]u8 {
        const old: [43]u8 = @splat('S');
        return gpa.dupe(u8, &old);
    }

    fn store(_: *anyopaque, _: []const u8, _: []const u8) acme.storage.Error!void {}

    fn delete(_: *anyopaque, _: []const u8) acme.storage.Error!void {}

    fn tryLock(_: *anyopaque, _: []const u8, _: []const u8, _: i64, _: u32) acme.storage.Error!bool {
        return true;
    }

    fn unlock(_: *anyopaque, _: []const u8, _: []const u8) void {}

    const vtable: acme.storage.Storage.VTable = .{ .load = load, .store = store, .delete = delete, .tryLock = tryLock, .unlock = unlock };
};

test "Storage.create without a backend create: the old value it looked at is wiped before it is freed" {
    try needsOptimized();
    var spy: Spy = .{ .child = testing.allocator, .watch_len = 43 };
    const s: acme.storage.Storage = .{ .ptr = &NoCreate.dummy, .vtable = &NoCreate.vtable };
    try testing.expect(!(try s.create(spy.allocator(), "k", "new")));
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
}

// Mutation run 2026-11-06, acme findings #1/#2: `Client.Certificate.deinit` and
// `x509.TlsAlpnCert.deinit` freed the private-key PEM without wiping it, while
// `Manager.Material.deinit` and the responder's store did.

test "Client.Certificate.deinit wipes the leaf key PEM before freeing it" {
    try needsOptimized();
    const key: [37]u8 = @splat('K');
    var spy: Spy = .{ .child = testing.allocator, .watch_len = key.len };
    const a = spy.allocator();
    var cert: acme.Certificate = .{ .chain_pem = try a.dupe(u8, "chain"), .key_pem = try a.dupe(u8, &key), .not_after = 1 };
    cert.deinit(a);
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
}

test "x509.TlsAlpnCert.deinit wipes the validation key PEM before freeing it" {
    try needsOptimized();
    const key: [37]u8 = @splat('K');
    var spy: Spy = .{ .child = testing.allocator, .watch_len = key.len };
    const a = spy.allocator();
    var cert: acme.x509.TlsAlpnCert = .{ .cert_der = try a.dupe(u8, "der"), .key_pem = try a.dupe(u8, &key) };
    cert.deinit(a);
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
}
