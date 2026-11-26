// SPDX-License-Identifier: MIT

//! wipealloc — an allocator adapter that zeroes every block before it goes back.
//!
//! `WipingAllocator` forwards `alloc` to its child and, on `free`, overwrites
//! the whole block with `std.crypto.secureZero` before handing it to the
//! child. `resize` and `remap` are refused, so a buffer never grows, shrinks
//! or moves without passing through `free`: `Allocator.realloc` then falls back
//! to alloc + copy + free, and the old block is wiped.
//!
//! Why refuse instead of forwarding: a shrink in place hands a tail back to
//! the child without a `free` (a page allocator unmaps it), and a moving
//! remap releases the old location the same way, so there is no hook left to
//! scrub it. Wiping a tail first would destroy data the caller still owns if
//! the child then refused.
//!
//! Which build mode this is for: `Allocator.free` memsets the block to
//! `undefined` before reaching the vtable, so in Debug and ReleaseSafe the
//! block is already scrubbed to `0xaa`. In ReleaseFast that memset compiles
//! away and this wipe is the only thing between a freed block and unrelated
//! code. Use it behind containers that hold secrets and grow (`ArrayList`,
//! `ArenaAllocator` chunks, a parser's tree).
//!
//! Not covered: stack copies, and memory the child never receives back
//! (a leak is a leak). The wipe is a volatile byte store loop (`secureZero`),
//! so it costs about one store per byte; an arena that holds no secrets does
//! not need it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const meta = .{
    .doc = "Allocator adapter that zeroes every block before it is freed and refuses resize/remap, so a growing secret-holding buffer never leaves an unwiped copy in the child allocator.",
    .platform_note = "any (portable)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant, // as thread-safe as the child allocator; the adapter holds no state of its own
    .model_after = "OpenSSL OPENSSL_clear_free / libsodium sodium_free: wipe on every give-back",
    .deps = .{},
};

pub const WipingAllocator = struct {
    child: Allocator,

    pub fn init(child: Allocator) WipingAllocator {
        return .{ .child = child };
    }

    /// The wiping allocator. The returned value points at `self`, which must
    /// outlive every block allocated through it and must not move.
    pub fn allocator(self: *WipingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, memory);
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

/// A locked, guard-paged allocator for key material (libsodium's `sodium_malloc`, OpenSSL's
/// `OPENSSL_secure_malloc`): every block gets its own mapping of whole pages, a `PROT_NONE` guard
/// page on each side, the block placed as far toward the upper guard as its alignment allows, a
/// random canary directly in front of it, the pages locked into RAM (`mlock`) and kept out of core
/// dumps (`MADV_DONTDUMP`), and the whole mapping zeroed and unmapped on `free`.
///
/// A write that runs past the end of a block faults on the guard page (a block whose length is a
/// multiple of its alignment ends exactly at it); a write before the block that reaches the canary
/// is found by `free`, which panics ("canary overwritten") rather than hand corrupted memory back
/// quietly, as libsodium aborts. `resize` and `remap` are refused, like `WipingAllocator`, so a
/// growing buffer is alloc + copy + `free` and the old block is wiped. The cost is two system
/// calls and at least three pages of address space per block: use it for a handful of keys, never
/// as the general-purpose allocator (a `std.ArrayList` of secrets behind `WipingAllocator` is the
/// cheap form). Linux only; blocks of alignment above the page size are refused (`null`).
pub const SecureAllocator = struct {
    /// What a failing `mlock` (`RLIMIT_MEMLOCK` is often 64 KiB or 8 MiB) does.
    lock: Lock = .best_effort,
    /// Written in front of every block, checked on `free`; random per allocator.
    canary: [canary_len]u8,

    pub const Lock = enum {
        /// Keep going unlocked: the guard pages and the wipe still apply (libsodium's behaviour).
        best_effort,
        /// The allocation fails (`null`, `error.OutOfMemory`) when the pages cannot be locked.
        required,
        /// Do not lock.
        off,
    };

    /// The canary ends where the block starts.
    pub const canary_len = 16;

    /// The canary is drawn from the kernel (`getrandom`); `error.RandomFailed` when it cannot be.
    pub fn init(lock: Lock) error{RandomFailed}!SecureAllocator {
        var self: SecureAllocator = .{ .lock = lock, .canary = undefined };
        var got: usize = 0;
        while (got < canary_len) {
            const rc = std.os.linux.getrandom(self.canary[got..].ptr, canary_len - got, 0);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => got += rc,
                .INTR => {},
                else => return error.RandomFailed,
            }
        }
        return self;
    }

    /// The secure allocator. The returned value points at `self`, which must outlive every block
    /// allocated through it and must not move.
    pub fn allocator(self: *SecureAllocator) Allocator {
        return .{ .ptr = self, .vtable = &secure_vtable };
    }

    /// Whether the canary in front of `block` (a slice this allocator returned) is intact.
    pub fn canaryIntact(self: *const SecureAllocator, block: []const u8) bool {
        const c = block.ptr - canary_len;
        return std.mem.eql(u8, c[0..canary_len], &self.canary);
    }

    const secure_vtable: Allocator.VTable = .{
        .alloc = secureAlloc,
        .resize = secureResize,
        .remap = secureRemap,
        .free = secureFree,
    };

    fn secureResize(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn secureRemap(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    /// The data pages' size for a block: its length, the canary and the slack of the alignment,
    /// rounded up to whole pages; null on overflow or past the 1 TiB cap.
    fn dataLen(len: usize, align_bytes: usize, page: usize) ?usize {
        const need = std.math.add(usize, len, canary_len + align_bytes) catch return null;
        const total = std.math.add(usize, need, page - 1) catch return null;
        const rounded = total / page * page;
        return if (rounded > (1 << 40)) null else rounded;
    }

    fn secureAlloc(ctx: *anyopaque, len: usize, alignment: Alignment, _: usize) ?[*]u8 {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        const linux = std.os.linux;
        const page = std.heap.pageSize();
        const align_bytes = alignment.toByteUnits();
        if (align_bytes > page or len == 0) return null;
        const data = dataLen(len, align_bytes, page) orelse return null;
        const map = std.posix.mmap(null, data + 2 * page, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch return null;
        const lo_guard = map.ptr;
        const hi_guard = map.ptr + page + data;
        if (linux.errno(linux.mprotect(lo_guard, page, .{})) != .SUCCESS or
            linux.errno(linux.mprotect(hi_guard, page, .{})) != .SUCCESS)
        {
            std.posix.munmap(map);
            return null;
        }
        const region = map.ptr + page;
        if (self.lock != .off and linux.errno(linux.mlock(region, data)) != .SUCCESS and self.lock == .required) {
            std.posix.munmap(map);
            return null;
        }
        _ = linux.madvise(region, data, linux.MADV.DONTDUMP); // best effort: only keeps the pages out of core dumps
        const end = @intFromPtr(region) + data;
        const user = std.mem.alignBackward(usize, end - len, align_bytes);
        const canary: [*]u8 = @ptrFromInt(user - canary_len);
        @memcpy(canary[0..canary_len], &self.canary);
        return @ptrFromInt(user);
    }

    fn secureFree(ctx: *anyopaque, memory: []u8, alignment: Alignment, _: usize) void {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        const page = std.heap.pageSize();
        const data = dataLen(memory.len, alignment.toByteUnits(), page).?; // what `secureAlloc` computed for this block
        const end = std.mem.alignForward(usize, @intFromPtr(memory.ptr) + memory.len, page);
        const region: [*]u8 = @ptrFromInt(end - data);
        if (!self.canaryIntact(memory)) @panic("wipealloc: canary overwritten (a write ran before the block)");
        std.crypto.secureZero(u8, region[0..data]);
        const map: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(end - data - page);
        std.posix.munmap(map[0 .. data + 2 * page]); // unmapping also unlocks the pages
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The CHILD of the adapter under test: passes through to `child` and, on
/// `free`, records whether the block the adapter handed back was all zero.
/// (`Allocator.free` poisons the block with 0xaa in Debug/ReleaseSafe before the
/// adapter sees it, so zeros here prove the adapter's own wipe in every mode.)
const Spy = struct {
    child: Allocator,
    frees: usize = 0,
    zero_frees: usize = 0,
    last_len: usize = 0,

    fn allocator(self: *Spy) Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = sAlloc, .resize = sResize, .remap = sRemap, .free = sFree } };
    }
    fn sAlloc(ctx: *anyopaque, len: usize, a: Alignment, ra: usize) ?[*]u8 {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, a, ra);
    }
    fn sResize(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn sRemap(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn sFree(ctx: *anyopaque, m: []u8, a: Alignment, ra: usize) void {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.frees += 1;
        self.last_len = m.len;
        if (std.mem.allEqual(u8, m, 0)) self.zero_frees += 1;
        self.child.rawFree(m, a, ra);
    }
};

test "free hands the child an all-zero block" {
    var spy: Spy = .{ .child = testing.allocator };
    var wa = WipingAllocator.init(spy.allocator());
    const a = wa.allocator();
    const buf = try a.alloc(u8, 100);
    @memset(buf, 0x5a);
    a.free(buf);
    try testing.expectEqual(@as(usize, 1), spy.frees);
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    try testing.expectEqual(@as(usize, 100), spy.last_len);
}

test "resize and remap are refused for growth, shrink and same size" {
    var wa = WipingAllocator.init(testing.allocator);
    const a = wa.allocator();
    const buf = try a.alloc(u8, 64);
    defer a.free(buf);
    try testing.expect(!a.resize(buf, 32));
    try testing.expect(!a.resize(buf, 64));
    try testing.expect(!a.resize(buf, 128));
    try testing.expect(a.remap(buf, 32) == null);
    try testing.expect(a.remap(buf, 128) == null);
}

test "realloc moves through alloc + copy + free: the old block is wiped, the data survives" {
    var spy: Spy = .{ .child = testing.allocator };
    var wa = WipingAllocator.init(spy.allocator());
    const a = wa.allocator();
    var buf = try a.alloc(u8, 16);
    for (buf, 0..) |*b, i| b.* = @intCast(i + 1);
    buf = try a.realloc(buf, 4096); // growth
    try testing.expectEqual(@as(usize, 1), spy.frees);
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    for (buf[0..16], 0..) |b, i| try testing.expectEqual(@as(u8, @intCast(i + 1)), b);
    buf = try a.realloc(buf, 8); // shrink
    try testing.expectEqual(@as(usize, 2), spy.frees);
    try testing.expectEqual(@as(usize, 2), spy.zero_frees);
    for (buf, 0..) |b, i| try testing.expectEqual(@as(u8, @intCast(i + 1)), b);
    a.free(buf);
    try testing.expectEqual(@as(usize, 3), spy.zero_frees);
}

test "the wipe covers the whole block, every alignment, and a zero-length free is harmless" {
    var spy: Spy = .{ .child = testing.allocator };
    var wa = WipingAllocator.init(spy.allocator());
    const a = wa.allocator();
    const wide = try a.alignedAlloc(u8, .@"64", 129);
    @memset(wide, 0xff);
    a.free(wide);
    try testing.expectEqual(@as(usize, 129), spy.last_len);
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    const empty = try a.alloc(u8, 0);
    a.free(empty); // never reaches the child: nothing to wipe, nothing to count
    try testing.expectEqual(@as(usize, 1), spy.frees);
}

test "an ArrayList that grows behind it leaves no secret in the child's freed blocks" {
    var backing: [4096]u8 = @splat(0);
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var wa = WipingAllocator.init(fba.allocator());
    const a = wa.allocator();
    var list: std.ArrayList(u8) = .empty;
    const secret = "correct horse battery staple";
    for (0..8) |_| try list.appendSlice(a, secret); // several reallocations
    list.deinit(a);
    try testing.expect(std.mem.indexOf(u8, &backing, secret) == null);
}

test "init and the struct literal are the same adapter; an allocation failure passes through" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var a1 = WipingAllocator.init(failing.allocator());
    var a2: WipingAllocator = .{ .child = failing.allocator() };
    try testing.expectError(error.OutOfMemory, a1.allocator().alloc(u8, 8));
    try testing.expectError(error.OutOfMemory, a2.allocator().alloc(u8, 8));
}

// ── SecureAllocator ─────────────────────────────────────────────────────────

/// Whether a read of one byte at `p` succeeds: `process_vm_readv` on this process reports
/// `EFAULT` for an unreadable page instead of raising a signal.
fn readable(p: [*]const u8) bool {
    var b: [1]u8 = undefined;
    const local = [_]std.posix.iovec{.{ .base = &b, .len = 1 }};
    const remote = [_]std.posix.iovec_const{.{ .base = p, .len = 1 }};
    const rc = std.os.linux.process_vm_readv(std.os.linux.getpid(), &local, &remote, 0);
    return std.os.linux.errno(rc) == .SUCCESS;
}

test "SecureAllocator: a block is usable, guard-paged on both sides, and its data pages are readable" {
    var sa = try SecureAllocator.init(.best_effort);
    const a = sa.allocator();
    const page = std.heap.pageSize();
    for ([_]usize{ 1, 7, 16, 100, page - 20, page, 3 * page + 5 }) |len| {
        const buf = try a.alloc(u8, len);
        defer a.free(buf);
        @memset(buf, 0xa5);
        try testing.expect(sa.canaryIntact(buf));
        try testing.expect(readable(buf.ptr));
        try testing.expect(readable(buf.ptr + len - 1));
        // The block ends flush against the upper guard page (alignment 1), the page after is unreadable.
        const end = std.mem.alignForward(usize, @intFromPtr(buf.ptr) + len, page);
        try testing.expectEqual(@intFromPtr(buf.ptr) + len, end);
        try testing.expect(!readable(@ptrFromInt(end)));
        // The data pages start `dataLen` bytes before that end; the page before them is a guard too.
        const first_data = end - SecureAllocator.dataLen(len, 1, page).?;
        try testing.expect(readable(@ptrFromInt(first_data)));
        try testing.expect(!readable(@ptrFromInt(first_data - page)));
    }
}

test "SecureAllocator: alignment is honoured up to the page size, larger is refused" {
    var sa = try SecureAllocator.init(.off);
    const a = sa.allocator();
    inline for (.{ 1, 8, 16, 64, 4096 }) |al| {
        const buf = try a.alignedAlloc(u8, .fromByteUnits(al), 24);
        defer a.free(buf);
        try testing.expectEqual(@as(usize, 0), @intFromPtr(buf.ptr) % al);
        try testing.expect(sa.canaryIntact(buf));
    }
    // Comptime alignment: `pageSize()` is a run-time query where the page
    // size varies (aarch64: 4K..64K), so take the comptime upper bound.
    try testing.expectError(error.OutOfMemory, a.alignedAlloc(u8, .fromByteUnits(2 * std.heap.page_size_max), 8));
    try testing.expectError(error.OutOfMemory, a.alloc(u8, std.math.maxInt(usize)));
    try testing.expectError(error.OutOfMemory, a.alloc(u8, 1 << 41));
}

test "SecureAllocator: the canary is per allocator, an overwritten one is seen, resize and remap are refused, realloc copies" {
    var s1 = try SecureAllocator.init(.off);
    var s2 = try SecureAllocator.init(.off);
    try testing.expect(!std.mem.eql(u8, &s1.canary, &s2.canary));
    const a = s1.allocator();
    const buf = try a.alloc(u8, 32);
    try testing.expect(!s2.canaryIntact(buf));
    try testing.expect(!a.resize(buf, 16));
    try testing.expect(a.remap(buf, 64) == null);
    @memset(buf, 0x11);
    const bigger = try a.realloc(buf, 5000);
    defer a.free(bigger);
    try testing.expect(std.mem.allEqual(u8, bigger[0..32], 0x11));
    try testing.expect(s1.canaryIntact(bigger));
    // A damaged canary is visible (and `free` would panic, so the block is restored first).
    bigger[0..].ptr[0] = 1;
    (bigger.ptr - 1)[0] ^= 0xff;
    try testing.expect(!s1.canaryIntact(bigger));
    (bigger.ptr - 1)[0] ^= 0xff;
    try testing.expect(s1.canaryIntact(bigger));
}

test "SecureAllocator: lock required fails when mlock does, best effort and off do not; many blocks come and go" {
    // A limit of 0 bytes of locked memory makes `mlock` fail (unless the process may exceed it).
    var old: std.os.linux.rlimit = undefined;
    _ = std.os.linux.getrlimit(.MEMLOCK, &old);
    var one = try SecureAllocator.init(.required);
    var two = try SecureAllocator.init(.best_effort);
    var three = try SecureAllocator.init(.off);
    const zero: std.os.linux.rlimit = .{ .cur = 0, .max = old.max };
    if (std.os.linux.errno(std.os.linux.setrlimit(.MEMLOCK, &zero)) != .SUCCESS) return error.SkipZigTest;
    defer _ = std.os.linux.setrlimit(.MEMLOCK, &old);
    // Root or CAP_IPC_LOCK ignores the limit: then `required` succeeds and there is nothing to see.
    if (one.allocator().alloc(u8, 8)) |b| {
        one.allocator().free(b);
    } else |e| try testing.expectEqual(error.OutOfMemory, e);
    for ([_]*SecureAllocator{ &two, &three }) |sa| {
        const a = sa.allocator();
        var blocks: [20][]u8 = undefined;
        for (&blocks, 0..) |*bp, i| bp.* = try a.alloc(u8, 10 + i);
        for (blocks) |bp| a.free(bp);
    }
}

test "SecureAllocator: free wipes the block's pages before unmapping" {
    // The mapping is gone after `free`, so the wipe is checked through a child of `WipingAllocator`
    // alone (above); here the data pages are inspected up to the `free` call.
    var sa = try SecureAllocator.init(.off);
    const a = sa.allocator();
    const buf = try a.alloc(u8, 64);
    @memset(buf, 0xee);
    a.free(buf);
    try testing.expect(!readable(buf.ptr)); // unmapped: a stale pointer faults instead of reading a secret
}

// ── whole-module mutation run 2026-11-25 ────────────────────────────────────

/// Contents of a /proc file (small or large), read through raw syscalls; the caller frees it.
fn readProc(path: [*:0]const u8) ![]u8 {
    const linux = std.os.linux;
    const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return error.SkipZigTest;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(testing.allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &chunk, chunk.len);
        if (linux.errno(n) != .SUCCESS) return error.SkipZigTest;
        if (n == 0) break;
        try out.appendSlice(testing.allocator, chunk[0..n]);
    }
    return out.toOwnedSlice(testing.allocator);
}

/// `VmLck` of this process, in kB.
fn vmLckKb() !usize {
    const text = try readProc("/proc/self/status");
    defer testing.allocator.free(text);
    const at = std.mem.find(u8, text, "VmLck:") orelse return error.SkipZigTest;
    var it = std.mem.tokenizeAny(u8, text[at + "VmLck:".len ..], " \t\n");
    return std.fmt.parseInt(usize, it.next() orelse return error.SkipZigTest, 10) catch error.SkipZigTest;
}

test "mutation 2026-11-25: dataLen rounds the canary, the alignment slack and the last byte into whole pages, and caps at 1 TiB" {
    const page = std.heap.pageSize();
    // The canary needs room: len + 1 + 16 spills over a page for len in [page - 16, page - 1].
    try testing.expectEqual(@as(?usize, 2 * page), SecureAllocator.dataLen(page - 5, 1, page));
    // len + 17 is exactly one byte over a page: that byte needs the next page.
    try testing.expectEqual(@as(?usize, 2 * page), SecureAllocator.dataLen(page - 16, 1, page));
    try testing.expectEqual(@as(?usize, page), SecureAllocator.dataLen(page - 17, 1, page));
    // The cap: exactly 1 TiB of data pages is allowed, one page more is not.
    try testing.expectEqual(@as(?usize, 1 << 40), SecureAllocator.dataLen((1 << 40) - 17, 1, page));
    try testing.expectEqual(@as(?usize, null), SecureAllocator.dataLen((1 << 40) - 16, 1, page));
    try testing.expectEqual(@as(?usize, null), SecureAllocator.dataLen(std.math.maxInt(usize) - 20, 1, page));
    try testing.expectEqual(@as(?usize, null), SecureAllocator.dataLen(std.math.maxInt(usize), 1, page));
}

test "mutation 2026-11-25: a zero-length request is refused by the allocator itself" {
    var sa = try SecureAllocator.init(.off);
    try testing.expect(sa.allocator().rawAlloc(0, .@"1", 0) == null);
}

test "mutation 2026-11-25: mlock is attempted for best_effort and required, never for off; blocks stay out of core dumps" {
    const page = std.heap.pageSize();
    var off = try SecureAllocator.init(.off);
    var best = try SecureAllocator.init(.best_effort);

    // Can this process lock memory at all (RLIMIT_MEMLOCK, capabilities)? Probe with a page of its own.
    {
        const probe = std.posix.mmap(null, page, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch return error.SkipZigTest;
        defer std.posix.munmap(probe);
        if (std.os.linux.errno(std.os.linux.mlock(probe.ptr, page)) != .SUCCESS) return error.SkipZigTest;
    }
    const before = try vmLckKb();
    const b_off = try off.allocator().alloc(u8, 100);
    const with_off = try vmLckKb();
    try testing.expectEqual(before, with_off); // .off locks nothing
    const b_best = try best.allocator().alloc(u8, 100);
    const with_best = try vmLckKb();
    try testing.expect(with_best >= with_off + page / 1024);

    // MADV_DONTDUMP: the block's mapping carries the `dd` flag in /proc/self/smaps.
    const smaps = try readProc("/proc/self/smaps");
    defer testing.allocator.free(smaps);
    const addr = @intFromPtr(b_best.ptr);
    var in_region = false;
    var has_dd = false;
    var lines = std.mem.splitScalar(u8, smaps, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.ascii.isHex(line[0]) and std.mem.findScalar(u8, line, '-') != null and std.mem.findScalar(u8, line, ' ') != null and !std.mem.startsWith(u8, line, "Vm")) {
            const dash = std.mem.findScalar(u8, line, '-').?;
            const sp = std.mem.findScalar(u8, line, ' ').?;
            if (dash < sp) {
                const lo = std.fmt.parseInt(usize, line[0..dash], 16) catch continue;
                const hi = std.fmt.parseInt(usize, line[dash + 1 .. sp], 16) catch continue;
                in_region = addr >= lo and addr < hi;
                continue;
            }
        }
        if (in_region and std.mem.startsWith(u8, line, "VmFlags:")) {
            var it = std.mem.tokenizeScalar(u8, line["VmFlags:".len..], ' ');
            while (it.next()) |f| if (std.mem.eql(u8, f, "dd")) {
                has_dd = true;
            };
        }
    }
    off.allocator().free(b_off);
    best.allocator().free(b_best);
    try testing.expect(has_dd);
}

test "mutation 2026-11-25: free unmaps the whole mapping, both guard pages and the data pages" {
    var sa = try SecureAllocator.init(.off);
    const a = sa.allocator();
    const page = std.heap.pageSize();
    const len: usize = 100;
    const buf = try a.alloc(u8, len);
    const end = std.mem.alignForward(usize, @intFromPtr(buf.ptr) + len, page);
    const first_data = end - SecureAllocator.dataLen(len, 1, page).?;
    a.free(buf);
    var vec: [1]u8 = undefined;
    // `mincore` answers ENOMEM for an address with no mapping at all (a PROT_NONE guard still counts as mapped).
    for ([_]usize{ end, first_data - page, first_data }) |p| {
        const rc = std.os.linux.mincore(@ptrFromInt(p), 1, &vec);
        try testing.expectEqual(std.os.linux.E.NOMEM, std.os.linux.errno(rc));
    }
}

test "mutation 2026-11-25: free of a block whose canary was overwritten aborts (child process)" {
    const linux = std.os.linux;
    const pid_rc = linux.fork();
    if (linux.errno(pid_rc) != .SUCCESS) return error.SkipZigTest;
    if (pid_rc == 0) {
        // The child: silence stderr and core dumps, then do what must abort.
        const null_fd = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
        if (linux.errno(null_fd) == .SUCCESS) _ = linux.dup2(@intCast(null_fd), 2);
        const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
        _ = linux.setrlimit(.CORE, &no_core);
        var sa = SecureAllocator.init(.off) catch linux.exit_group(3);
        const a = sa.allocator();
        const buf = a.alloc(u8, 32) catch linux.exit_group(4);
        (buf.ptr - 1)[0] ^= 0xff; // a write that ran before the block
        a.free(buf);
        linux.exit_group(0);
    }
    var status: i32 = 0;
    const w = linux.waitpid(@intCast(pid_rc), &status, 0);
    try testing.expectEqual(@as(usize, @intCast(pid_rc)), w);
    const st: u32 = @bitCast(status);
    try testing.expect(linux.W.IFSIGNALED(st));
    try testing.expectEqual(linux.SIG.ABRT, linux.W.TERMSIG(st));
}
