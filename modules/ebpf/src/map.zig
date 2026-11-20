// SPDX-License-Identifier: MIT
//! A map handle: lookup / update / delete / iterate, the batch commands, the
//! per-CPU value stride, and a comptime-typed wrapper. std offers the raw
//! `map_*_elem` wrappers over byte slices (and a `MapBatchAttr` that stops
//! before `count`); this is the layer a loader's user actually writes against.
//!
//! ## Per-CPU maps
//!
//! A per-CPU map's value, as the syscall sees it, is one slot **per possible
//! CPU**, each rounded up to 8 bytes (`round_up(value_size, 8)`), whatever the
//! map's own `value_size` is. A 4-byte value in a 128-CPU map is a 1024-byte
//! transfer. `Map.valueStride()` is that rounding, `perCpuBytes(ncpus)` the
//! total, and the wrong-size buffer is `error.BufferTooSmall` here, not a
//! kernel `EFAULT`/silent truncation. "Possible", not "online": a CPU that is
//! offline still has its slot (`perfbuf.possibleCpuCount`).
//!
//! ## Batch commands
//!
//! `lookupBatch`/`lookupAndDeleteBatch`/`updateBatch`/`deleteBatch` move up to
//! `count` elements in one syscall. The resume token is opaque and the kernel
//! copies `max(8, key_size)` bytes of it (a hash map keeps a bucket cursor, the
//! generic path the last key), so the caller's token buffer
//! (`Map.cursorSize()`) must be at least that large; a buffer of 8 for a map
//! with a 16-byte key would be overrun by the kernel.
//! A lookup that reaches the end returns `done = true` with the elements it
//! gathered (the kernel reports that as `ENOENT` *and* a valid `count`).

const std = @import("std");
const builtin = @import("builtin");

const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;
const linux = std.os.linux;
const BPF = linux.BPF;

const bpfsys = @import("bpfsys.zig");
const perfbuf = @import("perfbuf.zig");

pub const Error = error{
    PermissionDenied,
    InvalidArgument,
    /// `update` with `no_exist` found the key.
    KeyExists,
    /// `update` with `exist`, `delete` of a key that is not there (only when
    /// the call has no "not found" answer of its own).
    KeyNotFound,
    /// The map is full (`E2BIG`) or a hash map ran out of memory.
    MapFull,
    NotSupported,
    /// A key / value / token buffer is smaller than the map needs.
    BufferTooSmall,
    SystemResources,
    CpuEnumerationFailed,
    OutOfMemory,
    Unexpected,
};

fn mapErrno(e: linux.E) Error {
    return switch (e) {
        .PERM, .ACCES => error.PermissionDenied,
        .INVAL, .BADF, .FAULT => error.InvalidArgument,
        .EXIST => error.KeyExists,
        .NOENT => error.KeyNotFound,
        .@"2BIG" => error.MapFull,
        .NOSYS, .OPNOTSUPP => error.NotSupported,
        .NOMEM, .NOSPC, .MFILE, .NFILE => error.SystemResources,
        else => error.Unexpected,
    };
}

/// `BPF_ANY` / `BPF_NOEXIST` / `BPF_EXIST` (+ `BPF_F_LOCK`).
pub const UpdateFlags = enum(u64) {
    any = 0,
    no_exist = 1,
    exist = 2,
    lock = 4,
};

/// `union bpf_attr.batch`.
pub const BatchAttr = extern struct {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
};

const AttrBuf = extern union {
    base: BPF.Attr,
    map_elem: BPF.MapElemAttr,
    batch: BatchAttr,
};

pub const BatchResult = struct {
    /// Elements transferred.
    count: u32,
    /// A lookup / lookup-and-delete walked off the end of the map.
    done: bool,
};

/// `BPF_MAP_TYPE_*` values whose syscall value is one slot per possible CPU.
pub fn isPerCpuType(t: u32) bool {
    return switch (t) {
        5, // PERCPU_HASH
        6, // PERCPU_ARRAY
        10, // LRU_PERCPU_HASH
        21, // PERCPU_CGROUP_STORAGE
        => true,
        else => false,
    };
}

pub const Map = struct {
    fd: linux.fd_t,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,

    /// Describe the map behind `fd` (`BPF_OBJ_GET_INFO_BY_FD`). The fd stays
    /// the caller's.
    pub fn fromFd(fd: linux.fd_t) Error!Map {
        var info: bpfsys.MapInfo = std.mem.zeroes(bpfsys.MapInfo);
        bpfsys.objInfo(fd, std.mem.asBytes(&info)) catch |e| return switch (e) {
            error.PermissionDenied => error.PermissionDenied,
            error.NotSupported => error.NotSupported,
            else => error.InvalidArgument,
        };
        return .{
            .fd = fd,
            .map_type = info.type,
            .key_size = info.key_size,
            .value_size = info.value_size,
            .max_entries = info.max_entries,
            .map_flags = info.map_flags,
        };
    }

    pub fn isPerCpu(self: Map) bool {
        return isPerCpuType(self.map_type);
    }

    /// One CPU's slot in a per-CPU transfer: `value_size` rounded up to 8.
    pub fn valueStride(self: Map) usize {
        return std.mem.alignForward(usize, self.value_size, 8);
    }

    /// The bytes one element's value occupies in a syscall: `value_size`, or
    /// `valueStride() * ncpus` for a per-CPU map.
    pub fn valueBytes(self: Map, ncpus: u32) usize {
        return if (self.isPerCpu()) self.valueStride() * ncpus else self.value_size;
    }

    /// The number of CPUs a per-CPU transfer covers.
    pub fn possibleCpus(self: Map) Error!u32 {
        _ = self;
        return perfbuf.possibleCpuCount() catch error.CpuEnumerationFailed;
    }

    /// Size of the resume token every batch call needs.
    pub fn cursorSize(self: Map) usize {
        return @max(8, self.key_size);
    }

    fn checkKey(self: Map, key: []const u8) Error!void {
        if (key.len != self.key_size) return error.BufferTooSmall;
    }

    fn elem(self: Map, key: ?[]const u8, out: ?*anyopaque, flags: u64) AttrBuf {
        return .{ .map_elem = .{
            .map_fd = self.fd,
            .key = if (key) |k| @intFromPtr(k.ptr) else 0,
            .result = .{ .value = if (out) |o| @intFromPtr(o) else 0 },
            .flags = flags,
        } };
    }

    /// `BPF_MAP_LOOKUP_ELEM`. `value` must hold `valueBytes(ncpus)` bytes;
    /// returns `false` for a missing key.
    pub fn lookup(self: Map, key: []const u8, value: []u8, ncpus: u32) Error!bool {
        try self.checkKey(key);
        if (value.len < self.valueBytes(ncpus)) return error.BufferTooSmall;
        var buf = self.elem(key, value.ptr, 0);
        return self.run(.map_lookup_elem, &buf);
    }

    /// `BPF_MAP_LOOKUP_AND_DELETE_ELEM` (queues, stacks, hashes): the value
    /// is returned and the element removed.
    pub fn lookupAndDelete(self: Map, key: ?[]const u8, value: []u8, ncpus: u32) Error!bool {
        if (key) |k| try self.checkKey(k);
        if (value.len < self.valueBytes(ncpus)) return error.BufferTooSmall;
        var buf = self.elem(key, value.ptr, 0);
        return self.run(.map_lookup_and_delete_elem, &buf);
    }

    /// `BPF_MAP_UPDATE_ELEM`. A per-CPU `value` is the whole `valueBytes(ncpus)`
    /// slab (the kernel writes every CPU's slot from it). Queue/stack maps
    /// (`BPF_MAP_TYPE_QUEUE`/`STACK`) have no key: pass an empty one.
    pub fn update(self: Map, key: []const u8, value: []const u8, flags: UpdateFlags, ncpus: u32) Error!void {
        if (self.key_size != 0) try self.checkKey(key);
        if (value.len < self.valueBytes(ncpus)) return error.BufferTooSmall;
        var buf: AttrBuf = .{ .map_elem = .{
            .map_fd = self.fd,
            .key = if (key.len == 0) 0 else @intFromPtr(key.ptr),
            .result = .{ .value = @intFromPtr(value.ptr) },
            .flags = @backingInt(flags),
        } };
        const rc = linux.bpf(.map_update_elem, @ptrCast(&buf), @sizeOf(BPF.MapElemAttr));
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| return mapErrno(e),
        }
    }

    /// `BPF_MAP_DELETE_ELEM`; `false` when the key was not there.
    pub fn delete(self: Map, key: []const u8) Error!bool {
        try self.checkKey(key);
        var buf = self.elem(key, null, 0);
        return self.run(.map_delete_elem, &buf);
    }

    /// `BPF_MAP_GET_NEXT_KEY`: the key after `key` (`null`: the first), into
    /// `out`; `false` at the end. Iterating while deleting can restart the walk
    /// when the key you hold is deleted: the kernel then returns the first key.
    pub fn nextKey(self: Map, key: ?[]const u8, out: []u8) Error!bool {
        if (key) |k| try self.checkKey(k);
        if (out.len < self.key_size) return error.BufferTooSmall;
        var buf: AttrBuf = .{ .map_elem = .{
            .map_fd = self.fd,
            .key = if (key) |k| @intFromPtr(k.ptr) else 0,
            .result = .{ .next_key = @intFromPtr(out.ptr) },
            .flags = 0,
        } };
        return self.run(.map_get_next_key, &buf);
    }

    /// `BPF_MAP_FREEZE`: no more userspace writes, ever.
    pub fn freeze(self: Map) Error!void {
        var buf = self.elem(null, null, 0);
        const rc = linux.bpf(.map_freeze, @ptrCast(&buf), @sizeOf(BPF.MapElemAttr));
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| return mapErrno(e),
        }
    }

    fn run(self: Map, cmd: BPF.Cmd, buf: *AttrBuf) Error!bool {
        _ = self;
        const rc = linux.bpf(cmd, @ptrCast(buf), @sizeOf(BPF.MapElemAttr));
        return switch (linux.errno(rc)) {
            .SUCCESS => true,
            .NOENT => false,
            else => |e| mapErrno(e),
        };
    }

    // ── batch ───────────────────────────────────────────────────────────────

    /// Pure: the attr a batch command sends.
    pub fn buildBatchAttr(
        self: Map,
        cursor_in: ?[]const u8,
        cursor_out: ?[]u8,
        keys: []const u8,
        values: []const u8,
        count: u32,
    ) BatchAttr {
        return .{
            .in_batch = if (cursor_in) |c| @intFromPtr(c.ptr) else 0,
            .out_batch = if (cursor_out) |c| @intFromPtr(c.ptr) else 0,
            .keys = if (keys.len == 0) 0 else @intFromPtr(keys.ptr),
            .values = if (values.len == 0) 0 else @intFromPtr(values.ptr),
            .count = count,
            .map_fd = @intCast(self.fd),
            .elem_flags = 0,
            .flags = 0,
        };
    }

    fn batch(
        self: Map,
        cmd: BPF.Cmd,
        resume_from: ?[]const u8,
        next: ?[]u8,
        keys: []const u8,
        values: []const u8,
        count: u32,
        ncpus: u32,
    ) Error!BatchResult {
        if (count == 0) return .{ .count = 0, .done = false };
        const ksz = @as(usize, self.key_size) * count;
        const vsz = self.valueBytes(ncpus) * count;
        if (keys.len < ksz or (values.len != 0 and values.len < vsz)) return error.BufferTooSmall;
        if (resume_from) |c| if (c.len < self.cursorSize()) return error.BufferTooSmall;
        if (next) |c| if (c.len < self.cursorSize()) return error.BufferTooSmall;
        var buf: AttrBuf = .{ .batch = self.buildBatchAttr(resume_from, next, keys, values, count) };
        const rc = linux.bpf(cmd, @ptrCast(&buf), @sizeOf(BatchAttr));
        switch (linux.errno(rc)) {
            .SUCCESS => return .{ .count = buf.batch.count, .done = false },
            .NOENT => return .{ .count = buf.batch.count, .done = true },
            else => |e| return mapErrno(e),
        }
    }

    /// `BPF_MAP_LOOKUP_BATCH`: up to `count` key/value pairs. `resume_from` is
    /// `null` for the first call, then the `next` token of the previous one.
    pub fn lookupBatch(self: Map, resume_from: ?[]const u8, next: []u8, keys: []u8, values: []u8, count: u32, ncpus: u32) Error!BatchResult {
        return self.batch(.map_lookup_batch, resume_from, next, keys, values, count, ncpus);
    }

    /// `BPF_MAP_LOOKUP_AND_DELETE_BATCH` (hash maps).
    pub fn lookupAndDeleteBatch(self: Map, resume_from: ?[]const u8, next: []u8, keys: []u8, values: []u8, count: u32, ncpus: u32) Error!BatchResult {
        return self.batch(.map_lookup_and_delete_batch, resume_from, next, keys, values, count, ncpus);
    }

    /// `BPF_MAP_UPDATE_BATCH`: `count` pairs in one call; `result.count` is how
    /// many were applied (the kernel stops at the first failure).
    pub fn updateBatch(self: Map, keys: []const u8, values: []const u8, count: u32, ncpus: u32) Error!BatchResult {
        return self.batch(.map_update_batch, null, null, keys, values, count, ncpus);
    }

    /// `BPF_MAP_DELETE_BATCH`.
    pub fn deleteBatch(self: Map, keys: []const u8, count: u32) Error!BatchResult {
        return self.batch(.map_delete_batch, null, null, keys, &.{}, count, 0);
    }
};

// ── typed wrapper ───────────────────────────────────────────────────────────

/// A map whose key and value types are known at compile time. `init` checks
/// them against the kernel's description of the map once; after that every
/// call is sized by the types, so the buffer-size mistakes the byte-slice API
/// can make cannot be made. A per-CPU map's values come back as a slice of
/// `V`, one per possible CPU.
pub fn Typed(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        map: Map,

        pub const InitError = error{SizeMismatch} || Error;

        /// `K`/`V` must be exactly the map's key and value sizes.
        pub fn init(map: Map) InitError!Self {
            if (@sizeOf(K) != map.key_size or @sizeOf(V) != map.value_size) return error.SizeMismatch;
            return .{ .map = map };
        }

        pub fn get(self: Self, key: K) Error!?V {
            std.debug.assert(!self.map.isPerCpu()); // use getPerCpu
            var v: V = undefined;
            if (!try self.map.lookup(std.mem.asBytes(&key), std.mem.asBytes(&v), 0)) return null;
            return v;
        }

        pub fn put(self: Self, key: K, value: V, flags: UpdateFlags) Error!void {
            std.debug.assert(!self.map.isPerCpu());
            return self.map.update(std.mem.asBytes(&key), std.mem.asBytes(&value), flags, 0);
        }

        pub fn remove(self: Self, key: K) Error!bool {
            return self.map.delete(std.mem.asBytes(&key));
        }

        /// A per-CPU map: one `V` per possible CPU, allocated by `gpa`.
        pub fn getPerCpu(self: Self, gpa: std.mem.Allocator, key: K) Error!?[]V {
            const n = try self.map.possibleCpus();
            const slab = gpa.alloc(u8, self.map.valueBytes(n)) catch return error.OutOfMemory;
            defer gpa.free(slab);
            if (!try self.map.lookup(std.mem.asBytes(&key), slab, n)) return null;
            const out = gpa.alloc(V, n) catch return error.OutOfMemory;
            const stride = self.map.valueStride();
            for (out, 0..) |*o, i| @memcpy(std.mem.asBytes(o), slab[i * stride ..][0..@sizeOf(V)]);
            return out;
        }

        /// Walk every key (`BPF_MAP_GET_NEXT_KEY`).
        pub const Iterator = struct {
            map: Map,
            prev: ?K = null,

            pub fn next(self: *Iterator) Error!?K {
                var k: K = undefined;
                const have = try self.map.nextKey(if (self.prev) |*p| std.mem.asBytes(p) else null, std.mem.asBytes(&k));
                if (!have) return null;
                self.prev = k;
                return k;
            }
        };

        pub fn keys(self: Self) Iterator {
            return .{ .map = self.map };
        }
    };
}

// ── devmap / cpumap ─────────────────────────────────────────────────────────

/// `struct bpf_devmap_val`: what a `DEVMAP`/`DEVMAP_HASH` stores when created
/// with `value_size == 8` (`4` is `ifindex` alone).
pub const DevmapValue = extern struct {
    ifindex: u32,
    /// An `XDP` program of expected attach type `xdp_devmap`, run on
    /// redirected packets; 0 / negative: none.
    prog_fd: i32 = 0,
};

/// `struct bpf_cpumap_val`.
pub const CpumapValue = extern struct {
    /// The per-CPU queue size.
    qsize: u32,
    /// An `XDP` program of expected attach type `xdp_cpumap`; 0 / negative: none.
    prog_fd: i32 = 0,
};

/// Attach `prog_fd` (loaded from an `xdp/devmap` section) to a device-map
/// entry, redirecting to `ifindex`: the program runs on the packets redirected
/// through that entry. The map must have been created with `value_size == 8`.
pub fn devmapSet(map: Map, key: u32, ifindex: u32, prog_fd: ?linux.fd_t) Error!void {
    if (map.value_size != @sizeOf(DevmapValue)) {
        if (prog_fd != null or map.value_size != 4) return error.InvalidArgument;
    }
    const v: DevmapValue = .{ .ifindex = ifindex, .prog_fd = prog_fd orelse 0 };
    return map.update(std.mem.asBytes(&key), std.mem.asBytes(&v)[0..map.value_size], .any, 0);
}

/// Attach `prog_fd` (an `xdp/cpumap` program) to CPU `cpu`'s entry of a
/// `CPUMAP`, with queue size `qsize`. The map's `value_size` is 4 (queue size
/// only) or 8.
pub fn cpumapSet(map: Map, cpu: u32, qsize: u32, prog_fd: ?linux.fd_t) Error!void {
    if (map.value_size != @sizeOf(CpumapValue)) {
        if (prog_fd != null or map.value_size != 4) return error.InvalidArgument;
    }
    const v: CpumapValue = .{ .qsize = qsize, .prog_fd = prog_fd orelse 0 };
    return map.update(std.mem.asBytes(&cpu), std.mem.asBytes(&v)[0..map.value_size], .any, 0);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "BatchAttr matches <linux/bpf.h> union bpf_attr.batch (tools/uapi_layout.c)" {
    try testing.expectEqual(@as(usize, 0), @offsetOf(BatchAttr, "in_batch"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(BatchAttr, "out_batch"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(BatchAttr, "keys"));
    try testing.expectEqual(@as(usize, 24), @offsetOf(BatchAttr, "values"));
    try testing.expectEqual(@as(usize, 32), @offsetOf(BatchAttr, "count"));
    try testing.expectEqual(@as(usize, 36), @offsetOf(BatchAttr, "map_fd"));
    try testing.expectEqual(@as(usize, 40), @offsetOf(BatchAttr, "elem_flags"));
    try testing.expectEqual(@as(usize, 48), @offsetOf(BatchAttr, "flags"));
    try testing.expectEqual(@as(usize, 56), @sizeOf(BatchAttr));
    try testing.expectEqual(@as(usize, 8), @sizeOf(DevmapValue));
    try testing.expectEqual(@as(usize, 8), @sizeOf(CpumapValue));
}

fn testMap(map_type: u32, key: u32, value: u32) Map {
    return .{ .fd = 5, .map_type = map_type, .key_size = key, .value_size = value, .max_entries = 8, .map_flags = 0 };
}

test "per-CPU stride: value_size rounds up to 8 and multiplies by the possible CPUs" {
    const pc = testMap(6, 4, 4); // PERCPU_ARRAY, 4-byte value
    try testing.expect(pc.isPerCpu());
    try testing.expectEqual(@as(usize, 8), pc.valueStride());
    try testing.expectEqual(@as(usize, 8 * 128), pc.valueBytes(128));
    try testing.expectEqual(@as(usize, 16), testMap(5, 4, 9).valueStride());
    try testing.expectEqual(@as(usize, 8), testMap(5, 4, 8).valueStride());
    // an ordinary map is exactly value_size, whatever the CPU count
    const plain = testMap(2, 4, 12);
    try testing.expect(!plain.isPerCpu());
    try testing.expectEqual(@as(usize, 12), plain.valueBytes(64));
    for ([_]u32{ 5, 6, 10, 21 }) |t| try testing.expect(isPerCpuType(t));
    for ([_]u32{ 0, 1, 2, 4, 7, 9, 11, 12, 22, 27 }) |t| try testing.expect(!isPerCpuType(t));
    // the batch token must hold max(8, key_size)
    try testing.expectEqual(@as(usize, 8), testMap(1, 4, 4).cursorSize());
    try testing.expectEqual(@as(usize, 16), testMap(1, 16, 4).cursorSize());
}

test "buffers are checked before any syscall" {
    const m = testMap(1, 4, 8);
    var key: [4]u8 = undefined;
    var val: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, m.lookup(key[0..3], &val, 0));
    try testing.expectError(error.BufferTooSmall, m.lookup(&key, val[0..7], 0));
    try testing.expectError(error.BufferTooSmall, m.update(key[0..2], &val, .any, 0));
    try testing.expectError(error.BufferTooSmall, m.nextKey(null, key[0..3]));
    var keys: [16]u8 = undefined;
    var vals: [16]u8 = undefined;
    var tok: [8]u8 = undefined;
    // 4 elements need 16 key bytes and 32 value bytes
    try testing.expectError(error.BufferTooSmall, m.lookupBatch(null, &tok, &keys, &vals, 4, 0));
    // a per-CPU map's values are stride * cpus per element
    const pc = testMap(5, 4, 4);
    var small: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, pc.lookup(&key, &small, 2));
    // a 16-byte key needs a 16-byte token, not 8
    const big = testMap(1, 16, 4);
    var bk: [32]u8 = undefined;
    var bv: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, big.lookupBatch(null, &tok, &bk, &bv, 2, 0));
    // zero elements is not a syscall
    const none = try m.lookupBatch(null, &tok, &keys, &vals, 0, 0);
    try testing.expectEqual(@as(u32, 0), none.count);
}

test "buildBatchAttr: the exact fields" {
    const m = testMap(1, 4, 8);
    var keys: [8]u8 = undefined;
    var vals: [16]u8 = undefined;
    var tok_in: [8]u8 = undefined;
    var tok_out: [8]u8 = undefined;
    const a = m.buildBatchAttr(&tok_in, &tok_out, &keys, &vals, 2);
    try testing.expectEqual(@intFromPtr(&tok_in), a.in_batch);
    try testing.expectEqual(@intFromPtr(&tok_out), a.out_batch);
    try testing.expectEqual(@intFromPtr(&keys), a.keys);
    try testing.expectEqual(@intFromPtr(&vals), a.values);
    try testing.expectEqual(@as(u32, 2), a.count);
    try testing.expectEqual(@as(u32, 5), a.map_fd);
    const first = m.buildBatchAttr(null, &tok_out, &keys, &.{}, 1);
    try testing.expectEqual(@as(u64, 0), first.in_batch);
    try testing.expectEqual(@as(u64, 0), first.values);
}

test "devmapSet / cpumapSet: value size decides whether a program can be attached" {
    // value_size 4: ifindex only; a program is refused before any syscall
    const d4 = testMap(14, 4, 4);
    try testing.expectError(error.InvalidArgument, devmapSet(d4, 0, 2, 9));
    const d_bad = testMap(14, 4, 12);
    try testing.expectError(error.InvalidArgument, devmapSet(d_bad, 0, 2, null));
    const c4 = testMap(16, 4, 4);
    try testing.expectError(error.InvalidArgument, cpumapSet(c4, 0, 64, 9));
    const c_bad = testMap(16, 4, 2);
    try testing.expectError(error.InvalidArgument, cpumapSet(c_bad, 0, 64, null));
}

test "Typed: sizes are checked once, at init" {
    const m = testMap(2, 4, 8);
    const T = Typed(u32, u64);
    _ = try T.init(m);
    try testing.expectError(error.SizeMismatch, Typed(u64, u64).init(m));
    try testing.expectError(error.SizeMismatch, Typed(u32, u32).init(m));
}

test "unprivileged: a bogus map fd is an error, not a crash" {
    if (Map.fromFd(-1)) |_| {
        return error.TestUnexpectedResult;
    } else |e| try testing.expect(e == error.InvalidArgument or e == error.PermissionDenied or e == error.NotSupported);
    const m = testMap(2, 4, 8);
    var key: [4]u8 = @splat(0);
    var val: [8]u8 = undefined;
    if (m.lookup(&key, &val, 0)) |_| {
        return error.TestUnexpectedResult;
    } else |e| try testing.expect(e == error.InvalidArgument or e == error.PermissionDenied);
}
