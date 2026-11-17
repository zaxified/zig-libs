// SPDX-License-Identifier: MIT

//! Re-readable request body: drain `Request.reader()` once, read it again
//! from byte 0 as many times as needed.
//!
//! The shape the references converge on (ASP.NET Core `EnableBuffering`,
//! Rack 3 `RewindableInput`, Puma's Tempfile spill): the first
//! `Options.memory_limit` bytes stay in memory (default 30 KiB, ASP.NET's
//! `bufferThreshold` of 30720), the rest goes to a spool the CALLER supplies
//! (`SpoolSource`), and `Options.max_total` caps the whole body
//! (`error.BodyTooLarge`, which the caller answers with 413 as before). `http`
//! keeps no filesystem policy: `FileSpool` is a spool over a file the caller
//! opened (an `O_TMPFILE` / unlinked temp file is the intended use).
//!
//! Opt-in and additive: nothing in the server uses it on its own, so the
//! default per-request memory is unchanged. The server's own body cap
//! (`Options.max_body_bytes`, the h2 body budget) still bounds what
//! `Request.reader()` yields underneath, and its read timeouts still apply
//! while `fill` drains it.
//!
//! The body may hold secrets: `deinit` wipes the memory part and the staging
//! buffers, and `FileSpool.deinit` truncates its file to 0 bytes. The spool's
//! storage is the caller's security boundary.

const std = @import("std");
const Server = @import("Server.zig");
const Io = std.Io;
const Reader = Io.Reader;
const Writer = Io.Writer;
const Allocator = std.mem.Allocator;

/// ASP.NET Core's `FileBufferingReadStream` default `bufferThreshold`.
pub const default_memory_limit: usize = 30 * 1024;

/// Storage for the part of a body past `Options.memory_limit`, written once
/// front to back, then read back by offset any number of times.
pub const BodySpool = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Append `bytes` at the current end.
        append: *const fn (ctx: *anyopaque, bytes: []const u8) error{SpoolWriteFailed}!void,
        /// Read up to `buf.len` bytes starting at `offset`; 0 only past the end.
        readAt: *const fn (ctx: *anyopaque, offset: u64, buf: []u8) error{SpoolReadFailed}!usize,
        /// Release the spool (and wipe or truncate what it stored).
        deinit: *const fn (ctx: *anyopaque) void,
    };
};

/// Opens a fresh `BodySpool` for one body, only once that body grows past
/// `Options.memory_limit` (a small body never opens one).
pub const SpoolSource = struct {
    ctx: ?*anyopaque = null,
    open: *const fn (ctx: ?*anyopaque) error{ SpoolOpenFailed, OutOfMemory }!BodySpool,
};

/// Sees every body byte once, in order, as `fill` takes it (e.g. a hash, so
/// the body is digested in the same pass that buffers it).
pub const Tap = struct {
    ctx: *anyopaque,
    observe: *const fn (ctx: *anyopaque, bytes: []const u8) void,
};

pub const Options = struct {
    /// Bytes kept in memory (grown on demand, never preallocated).
    memory_limit: usize = default_memory_limit,
    /// Cap on the whole body; null = only the server's own body cap.
    max_total: ?u64 = null,
    /// Where bytes past `memory_limit` go; null = such a body is
    /// `error.BodyTooLarge`.
    spool: ?SpoolSource = null,
    tap: ?*const Tap = null,
};

pub const FillError = error{ BodyTooLarge, ReadFailed, OutOfMemory, SpoolOpenFailed, SpoolWriteFailed };

pub const RewindableBody = struct {
    gpa: Allocator,
    opts: Options,
    mem: []u8 = &.{},
    mem_len: usize = 0,
    spool: ?BodySpool = null,
    total: u64 = 0,
    filled: bool = false,
    spool_read_failed: bool = false,
    pos: u64 = 0,
    stage: [4096]u8 = undefined,
    stage_pos: usize = 0,
    stage_len: usize = 0,
    rd: Reader = undefined,
    rd_buf: [1024]u8 = undefined,

    pub fn init(rb: *RewindableBody, gpa: Allocator, opts: Options) void {
        rb.* = .{ .gpa = gpa, .opts = opts };
    }

    /// Wipes and frees the memory part, wipes the staging buffers, releases
    /// the spool. Idempotent.
    pub fn deinit(rb: *RewindableBody) void {
        std.crypto.secureZero(u8, rb.mem);
        rb.gpa.free(rb.mem);
        std.crypto.secureZero(u8, &rb.stage);
        std.crypto.secureZero(u8, &rb.rd_buf);
        if (rb.spool) |sp| sp.vtable.deinit(sp.ctx);
        rb.mem = &.{};
        rb.mem_len = 0;
        rb.spool = null;
    }

    /// Body length in bytes (valid after `fill`).
    pub fn len(rb: *const RewindableBody) u64 {
        return rb.total;
    }

    /// Whether the body went past `memory_limit` into the spool.
    pub fn spooled(rb: *const RewindableBody) bool {
        return rb.spool != null;
    }

    /// Drains `src` to its end. Call once. `error.BodyTooLarge` when the body
    /// passes `max_total`, or `memory_limit` with no spool; a read error or a
    /// spool failure is never `BodyTooLarge` (it is not the client's size).
    pub fn fill(rb: *RewindableBody, src: *Reader) FillError!void {
        std.debug.assert(!rb.filled);
        rb.filled = true;
        const limit = rb.opts.memory_limit;
        while (true) {
            if (rb.mem_len == rb.mem.len) {
                if (rb.mem.len >= limit) break;
                try rb.grow(@min(@max(rb.mem.len *| 2, 256), limit));
            }
            const want = rb.mem.len - rb.mem_len;
            const n = try src.readSliceShort(rb.mem[rb.mem_len..]);
            try rb.took(rb.mem[rb.mem_len..][0..n]);
            rb.mem_len += n;
            if (n < want) return;
        }
        const source = rb.opts.spool orelse {
            var one: [1]u8 = undefined;
            if (try src.readSliceShort(&one) == 0) return;
            return error.BodyTooLarge;
        };
        while (true) {
            const n = try src.readSliceShort(&rb.stage);
            if (n == 0) return;
            try rb.took(rb.stage[0..n]);
            if (rb.spool == null) rb.spool = try source.open(source.ctx);
            const sp = rb.spool.?;
            try sp.vtable.append(sp.ctx, rb.stage[0..n]);
            if (n < rb.stage.len) return;
        }
    }

    fn took(rb: *RewindableBody, bytes: []const u8) error{BodyTooLarge}!void {
        rb.total += bytes.len;
        if (rb.opts.max_total) |max| if (rb.total > max) return error.BodyTooLarge;
        if (bytes.len == 0) return;
        if (rb.opts.tap) |t| t.observe(t.ctx, bytes);
    }

    fn grow(rb: *RewindableBody, cap: usize) error{OutOfMemory}!void {
        const fresh = try rb.gpa.alloc(u8, cap);
        @memcpy(fresh[0..rb.mem_len], rb.mem[0..rb.mem_len]);
        std.crypto.secureZero(u8, rb.mem);
        rb.gpa.free(rb.mem);
        rb.mem = fresh;
    }

    /// A reader over the whole body from byte 0. Every call rewinds; the
    /// previous reader returned by this or `install` restarts too.
    pub fn reader(rb: *RewindableBody) *Reader {
        std.debug.assert(rb.filled);
        rb.pos = 0;
        rb.stage_pos = 0;
        rb.stage_len = 0;
        rb.spool_read_failed = false;
        rb.rd = .{ .vtable = &.{ .stream = stream }, .buffer = &rb.rd_buf, .seek = 0, .end = 0 };
        return &rb.rd;
    }

    /// Points `req.reader()` at a rewound reader over this body (the
    /// `Request.decoded` seam). Returns the previous override; restore it
    /// with `req.decoded = prev` before `rb` goes away.
    pub fn install(rb: *RewindableBody, req: *Server.Request) ?*Reader {
        const prev = req.decoded;
        req.decoded = rb.reader();
        return prev;
    }

    fn stream(r: *Reader, w: *Writer, limit: Io.Limit) Reader.StreamError!usize {
        const rb: *RewindableBody = @alignCast(@fieldParentPtr("rd", r));
        if (rb.pos >= rb.total) return error.EndOfStream;
        if (rb.pos < rb.mem_len) {
            const from: usize = @intCast(rb.pos);
            const n = try w.write(limit.slice(rb.mem[from..rb.mem_len]));
            rb.pos += n;
            return n;
        }
        if (rb.stage_pos == rb.stage_len) {
            if (rb.spool_read_failed) return error.ReadFailed;
            const sp = rb.spool.?;
            const want: usize = @intCast(@min(rb.stage.len, rb.total - rb.pos));
            const got = sp.vtable.readAt(sp.ctx, rb.pos - rb.mem_len, rb.stage[0..want]) catch {
                rb.spool_read_failed = true;
                return error.ReadFailed;
            };
            if (got == 0 or got > want) {
                rb.spool_read_failed = true;
                return error.ReadFailed;
            }
            rb.stage_pos = 0;
            rb.stage_len = got;
        }
        const n = try w.write(limit.slice(rb.stage[rb.stage_pos..rb.stage_len]));
        rb.stage_pos += n;
        rb.pos += n;
        return n;
    }
};

/// A `BodySpool` over a file the caller opened (read + write). `deinit`
/// truncates the file to 0 bytes; a spool made by `create` also closes the
/// file and frees itself (the shape a `SpoolSource.open` returns).
pub const FileSpool = struct {
    io: Io,
    file: Io.File,
    len: u64 = 0,
    owner: ?Allocator = null,

    /// The caller keeps the file and the `FileSpool`.
    pub fn init(io: Io, file: Io.File) FileSpool {
        return .{ .io = io, .file = file };
    }

    /// The spool owns `file` and itself: its `BodySpool.deinit` truncates,
    /// closes the file and frees the spool.
    pub fn create(gpa: Allocator, io: Io, file: Io.File) error{OutOfMemory}!*FileSpool {
        const fs = try gpa.create(FileSpool);
        fs.* = .{ .io = io, .file = file, .owner = gpa };
        return fs;
    }

    pub fn spool(fs: *FileSpool) BodySpool {
        return .{ .ctx = fs, .vtable = &vtable };
    }

    const vtable: BodySpool.VTable = .{ .append = append, .readAt = readAt, .deinit = release };

    fn append(ctx: *anyopaque, bytes: []const u8) error{SpoolWriteFailed}!void {
        const fs: *FileSpool = @ptrCast(@alignCast(ctx));
        fs.file.writePositionalAll(fs.io, bytes, fs.len) catch return error.SpoolWriteFailed;
        fs.len += bytes.len;
    }

    fn readAt(ctx: *anyopaque, offset: u64, buf: []u8) error{SpoolReadFailed}!usize {
        const fs: *FileSpool = @ptrCast(@alignCast(ctx));
        if (offset >= fs.len) return 0;
        const want: usize = @intCast(@min(buf.len, fs.len - offset));
        return fs.file.readPositional(fs.io, &.{buf[0..want]}, offset) catch error.SpoolReadFailed;
    }

    fn release(ctx: *anyopaque) void {
        const fs: *FileSpool = @ptrCast(@alignCast(ctx));
        fs.deinit();
    }

    /// Truncates the file to 0; a `create`d spool also closes it and frees itself.
    pub fn deinit(fs: *FileSpool) void {
        fs.file.setLength(fs.io, 0) catch {};
        fs.len = 0;
        if (fs.owner) |gpa| {
            fs.file.close(fs.io);
            gpa.destroy(fs);
        }
    }
};

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");

/// In-memory test spool with failure switches.
const MemSpool = struct {
    gpa: Allocator,
    data: std.ArrayList(u8) = .empty,
    fail_append: bool = false,
    fail_read: bool = false,
    released: bool = false,
    releases: u32 = 0,
    lie: bool = false,
    opens: u32 = 0,
    fail_open: bool = false,

    fn source(ms: *MemSpool) SpoolSource {
        return .{ .ctx = ms, .open = open };
    }
    fn open(ctx: ?*anyopaque) error{ SpoolOpenFailed, OutOfMemory }!BodySpool {
        const ms: *MemSpool = @ptrCast(@alignCast(ctx.?));
        if (ms.fail_open) return error.SpoolOpenFailed;
        ms.opens += 1;
        return .{ .ctx = ms, .vtable = &vt };
    }
    const vt: BodySpool.VTable = .{ .append = append, .readAt = readAt, .deinit = release };
    fn append(ctx: *anyopaque, bytes: []const u8) error{SpoolWriteFailed}!void {
        const ms: *MemSpool = @ptrCast(@alignCast(ctx));
        if (ms.fail_append) return error.SpoolWriteFailed;
        ms.data.appendSlice(ms.gpa, bytes) catch return error.SpoolWriteFailed;
    }
    fn readAt(ctx: *anyopaque, offset: u64, buf: []u8) error{SpoolReadFailed}!usize {
        const ms: *MemSpool = @ptrCast(@alignCast(ctx));
        if (ms.fail_read) return error.SpoolReadFailed;
        if (offset >= ms.data.items.len) return 0;
        const o: usize = @intCast(offset);
        const n = @min(buf.len, ms.data.items.len - o);
        @memcpy(buf[0..n], ms.data.items[o..][0..n]);
        return if (ms.lie) n + 1 else n;
    }
    fn release(ctx: *anyopaque) void {
        const ms: *MemSpool = @ptrCast(@alignCast(ctx));
        ms.released = true;
        ms.releases += 1;
    }
    fn deinit(ms: *MemSpool) void {
        ms.data.deinit(ms.gpa);
    }
};

fn pattern(buf: []u8, seed: u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% seed);
}

fn readAllInto(r: *Reader, gpa: Allocator) ![]u8 {
    return r.allocRemaining(gpa, .unlimited);
}

test "RewindableBody: a body under memory_limit re-reads identically three times, no spool opened" {
    var body: [1000]u8 = undefined;
    pattern(&body, 7);
    var src: Reader = .fixed(&body);
    var ms: MemSpool = .{ .gpa = testing.allocator };
    defer ms.deinit();
    var rb: RewindableBody = undefined;
    rb.init(testing.allocator, .{ .memory_limit = 4096, .spool = ms.source() });
    defer rb.deinit();
    try rb.fill(&src);
    try testing.expectEqual(@as(u64, body.len), rb.len());
    try testing.expect(!rb.spooled());
    try testing.expectEqual(@as(u32, 0), ms.opens);
    for (0..3) |_| {
        const got = try readAllInto(rb.reader(), testing.allocator);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &body, got);
    }
}

test "RewindableBody: memory -> spool switch at the exact boundary, and one byte past it" {
    inline for (.{ 0, 1, 4097, 9000 }) |extra| {
        const limit = 512;
        var body: [limit + extra]u8 = undefined;
        pattern(&body, 3);
        var src: Reader = .fixed(&body);
        var ms: MemSpool = .{ .gpa = testing.allocator };
        defer ms.deinit();
        var rb: RewindableBody = undefined;
        rb.init(testing.allocator, .{ .memory_limit = limit, .spool = ms.source() });
        try rb.fill(&src);
        try testing.expectEqual(@as(u64, body.len), rb.len());
        try testing.expectEqual(extra != 0, rb.spooled());
        try testing.expectEqual(@as(usize, extra), ms.data.items.len);
        try testing.expectEqual(@as(u32, @intFromBool(extra != 0)), ms.opens); // one spool per body, never one per chunk
        for (0..2) |_| {
            const got = try readAllInto(rb.reader(), testing.allocator);
            defer testing.allocator.free(got);
            try testing.expectEqualSlices(u8, &body, got);
        }
        rb.deinit();
        try testing.expectEqual(extra != 0, ms.released);
    }
}

test "RewindableBody: past memory_limit with no spool is BodyTooLarge; exactly at it is fine" {
    var body: [300]u8 = undefined;
    pattern(&body, 1);
    {
        var src: Reader = .fixed(body[0..256]);
        var rb: RewindableBody = undefined;
        rb.init(testing.allocator, .{ .memory_limit = 256 });
        defer rb.deinit();
        try rb.fill(&src);
        try testing.expectEqual(@as(u64, 256), rb.len());
    }
    {
        var src: Reader = .fixed(body[0..257]);
        var rb: RewindableBody = undefined;
        rb.init(testing.allocator, .{ .memory_limit = 256 });
        defer rb.deinit();
        try testing.expectError(error.BodyTooLarge, rb.fill(&src));
    }
}

test "RewindableBody: max_total is BodyTooLarge one byte over, in memory and in the spool" {
    var body: [5000]u8 = undefined;
    pattern(&body, 9);
    inline for (.{ 100, 4000 }) |max| {
        var ms: MemSpool = .{ .gpa = testing.allocator };
        defer ms.deinit();
        {
            var src: Reader = .fixed(body[0..max]);
            var rb: RewindableBody = undefined;
            rb.init(testing.allocator, .{ .memory_limit = 1024, .max_total = max, .spool = ms.source() });
            defer rb.deinit();
            try rb.fill(&src);
        }
        {
            var src: Reader = .fixed(body[0 .. max + 1]);
            var rb: RewindableBody = undefined;
            rb.init(testing.allocator, .{ .memory_limit = 1024, .max_total = max, .spool = ms.source() });
            defer rb.deinit();
            try testing.expectError(error.BodyTooLarge, rb.fill(&src));
        }
    }
}

test "RewindableBody: spool open/append failures are their own errors, a read-back failure is ReadFailed" {
    var body: [2000]u8 = undefined;
    pattern(&body, 5);
    {
        var ms: MemSpool = .{ .gpa = testing.allocator, .fail_open = true };
        defer ms.deinit();
        var src: Reader = .fixed(&body);
        var rb: RewindableBody = undefined;
        rb.init(testing.allocator, .{ .memory_limit = 256, .spool = ms.source() });
        defer rb.deinit();
        try testing.expectError(error.SpoolOpenFailed, rb.fill(&src));
    }
    {
        var ms: MemSpool = .{ .gpa = testing.allocator, .fail_append = true };
        defer ms.deinit();
        var src: Reader = .fixed(&body);
        var rb: RewindableBody = undefined;
        rb.init(testing.allocator, .{ .memory_limit = 256, .spool = ms.source() });
        defer rb.deinit();
        try testing.expectError(error.SpoolWriteFailed, rb.fill(&src));
    }
    {
        var ms: MemSpool = .{ .gpa = testing.allocator };
        defer ms.deinit();
        var src: Reader = .fixed(&body);
        var rb: RewindableBody = undefined;
        rb.init(testing.allocator, .{ .memory_limit = 256, .spool = ms.source() });
        defer rb.deinit();
        try rb.fill(&src);
        ms.fail_read = true;
        try testing.expectError(error.ReadFailed, readAllInto(rb.reader(), testing.allocator));
        // A rewind clears the latched failure once the spool recovers.
        ms.fail_read = false;
        const got = try readAllInto(rb.reader(), testing.allocator);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &body, got);
    }
}

test "RewindableBody: a source read error is ReadFailed, never BodyTooLarge" {
    const Failing = struct {
        fn stream(_: *Reader, _: *Writer, _: Io.Limit) Reader.StreamError!usize {
            return error.ReadFailed;
        }
    };
    var buf: [16]u8 = undefined;
    var src: Reader = .{ .vtable = &.{ .stream = Failing.stream }, .buffer = &buf, .seek = 0, .end = 0 };
    var rb: RewindableBody = undefined;
    rb.init(testing.allocator, .{ .memory_limit = 64 });
    defer rb.deinit();
    try testing.expectError(error.ReadFailed, rb.fill(&src));
}

test "RewindableBody: the tap sees every byte once, in order (incremental SHA-256 == one-shot)" {
    var body: [7000]u8 = undefined;
    pattern(&body, 11);
    const H = struct {
        h: std.crypto.hash.sha2.Sha256 = .init(.{}),
        fn observe(ctx: *anyopaque, bytes: []const u8) void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            s.h.update(bytes);
        }
    };
    var hs: H = .{};
    const tap: Tap = .{ .ctx = &hs, .observe = H.observe };
    var ms: MemSpool = .{ .gpa = testing.allocator };
    defer ms.deinit();
    var src: Reader = .fixed(&body);
    var rb: RewindableBody = undefined;
    rb.init(testing.allocator, .{ .memory_limit = 1000, .spool = ms.source(), .tap = &tap });
    defer rb.deinit();
    try rb.fill(&src);
    var got: [32]u8 = undefined;
    hs.h.final(&got);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&body, &want, .{});
    try testing.expectEqualSlices(u8, &want, &got);
}

test "RewindableBody: out of memory at every allocation is OutOfMemory, no leak" {
    var body: [3000]u8 = undefined;
    pattern(&body, 2);
    var i: usize = 0;
    while (true) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        var src: Reader = .fixed(&body);
        var rb: RewindableBody = undefined;
        rb.init(fa.allocator(), .{ .memory_limit = 4096 });
        const res = rb.fill(&src);
        rb.deinit();
        if (res) |_| break else |e| try testing.expectEqual(error.OutOfMemory, e);
    }
    try testing.expect(i > 0);
}

test "RewindableBody: deinit wipes the memory part before freeing it" {
    // `Allocator.free` overwrites with `undefined` before the free reaches the
    // allocator, which in Debug/ReleaseSafe hides a missing wipe: only the
    // unchecked modes can see it.
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
    const Watch = struct {
        child: Allocator,
        saw_nonzero_on_free: bool = false,
        fn allocator(w: *@This()) Allocator {
            return .{ .ptr = w, .vtable = &.{ .alloc = alloc, .resize = Allocator.noResize, .remap = Allocator.noRemap, .free = free } };
        }
        fn alloc(ctx: *anyopaque, n: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
            const w: *@This() = @ptrCast(@alignCast(ctx));
            return w.child.rawAlloc(n, a, ra);
        }
        fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
            const w: *@This() = @ptrCast(@alignCast(ctx));
            for (m) |b| if (b == 0xA5) {
                w.saw_nonzero_on_free = true;
            };
            w.child.rawFree(m, a, ra);
        }
    };
    var w: Watch = .{ .child = testing.allocator };
    var body: [900]u8 = undefined;
    @memset(&body, 0xA5);
    var src: Reader = .fixed(&body);
    var rb: RewindableBody = undefined;
    rb.init(w.allocator(), .{ .memory_limit = 4096 });
    try rb.fill(&src);
    rb.deinit();
    try testing.expect(!w.saw_nonzero_on_free);
}

test "FileSpool: spills to a real file, re-reads, and deinit truncates it to 0" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "spool.bin", .{ .read = true, .truncate = true });
    defer file.close(io);
    var fs = FileSpool.init(io, file);
    const Src = struct {
        sp: *FileSpool,
        fn open(ctx: ?*anyopaque) error{ SpoolOpenFailed, OutOfMemory }!BodySpool {
            const s: *@This() = @ptrCast(@alignCast(ctx.?));
            return s.sp.spool();
        }
    };
    var s: Src = .{ .sp = &fs };
    var body: [20_000]u8 = undefined;
    pattern(&body, 13);
    var src: Reader = .fixed(&body);
    var rb: RewindableBody = undefined;
    rb.init(testing.allocator, .{ .memory_limit = 2048, .spool = .{ .ctx = &s, .open = Src.open } });
    try rb.fill(&src);
    try testing.expect(rb.spooled());
    try testing.expectEqual(@as(u64, body.len - 2048), fs.len);
    for (0..2) |_| {
        const got = try readAllInto(rb.reader(), testing.allocator);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &body, got);
    }
    rb.deinit();
    try testing.expectEqual(@as(u64, 0), try file.length(io));
}

test "FileSpool.create: the spool owns and closes its file" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "owned.bin", .{ .read = true, .truncate = true });
    const fs = try FileSpool.create(testing.allocator, io, file);
    const sp = fs.spool();
    try sp.vtable.append(sp.ctx, "hello spool");
    var buf: [32]u8 = undefined;
    const n = try sp.vtable.readAt(sp.ctx, 6, &buf);
    try testing.expectEqualStrings("spool", buf[0..n]);
    try testing.expectEqual(@as(usize, 0), try sp.vtable.readAt(sp.ctx, 11, &buf));
    sp.vtable.deinit(sp.ctx); // truncates, closes, frees (testing.allocator checks the free)
    const st = try tmp.dir.statFile(io, "owned.bin", .{});
    try testing.expectEqual(@as(u64, 0), st.size);
}

const CountTap = struct {
    calls: u32 = 0,
    empty_calls: u32 = 0,
    bytes: u64 = 0,
    fn observe(ctx: *anyopaque, bytes: []const u8) void {
        const t: *CountTap = @ptrCast(@alignCast(ctx));
        t.calls += 1;
        if (bytes.len == 0) t.empty_calls += 1;
        t.bytes += bytes.len;
    }
};

test "RewindableBody: a memory_limit that is not a power of two is honoured exactly (the doubling never overshoots it)" {
    var body: [1500]u8 = undefined;
    pattern(&body, 4);
    inline for (.{ 1000, 1001, 1500 }) |n| {
        var ms: MemSpool = .{ .gpa = testing.allocator };
        defer ms.deinit();
        var src: Reader = .fixed(body[0..n]);
        var rb: RewindableBody = undefined;
        rb.init(testing.allocator, .{ .memory_limit = 1000, .spool = ms.source() });
        defer rb.deinit();
        try rb.fill(&src);
        try testing.expectEqual(@as(usize, n - 1000), ms.data.items.len);
        try testing.expectEqual(n > 1000, rb.spooled());
        try testing.expect(rb.mem.len <= 1000);
    }
}

test "RewindableBody: the tap is never handed an empty slice and sees exactly the body, with and without a spool" {
    var body: [6000]u8 = undefined;
    pattern(&body, 21);
    inline for (.{ 0, 100, 1024, 6000 }) |n| {
        var ct: CountTap = .{};
        const tap: Tap = .{ .ctx = &ct, .observe = CountTap.observe };
        var ms: MemSpool = .{ .gpa = testing.allocator };
        defer ms.deinit();
        var src: Reader = .fixed(body[0..n]);
        var rb: RewindableBody = undefined;
        rb.init(testing.allocator, .{ .memory_limit = 1024, .spool = ms.source(), .tap = &tap });
        defer rb.deinit();
        try rb.fill(&src);
        try testing.expectEqual(@as(u32, 0), ct.empty_calls);
        try testing.expectEqual(@as(u64, n), ct.bytes);
    }
}

test "RewindableBody: deinit wipes the staging and reader buffers, resets, and is idempotent" {
    var body: [3000]u8 = undefined;
    @memset(&body, 0xA5);
    var ms: MemSpool = .{ .gpa = testing.allocator };
    defer ms.deinit();
    var src: Reader = .fixed(&body);
    var rb: RewindableBody = undefined;
    rb.init(testing.allocator, .{ .memory_limit = 512, .spool = ms.source() });
    try rb.fill(&src);
    const got = try readAllInto(rb.reader(), testing.allocator);
    testing.allocator.free(got);
    _ = try rb.reader().peek(10); // fills the reader's own buffer
    try testing.expect(std.mem.findScalar(u8, &rb.stage, 0xA5) != null);
    try testing.expect(std.mem.findScalar(u8, &rb.rd_buf, 0xA5) != null);
    rb.deinit();
    try testing.expectEqual(@as(?usize, null), std.mem.findScalar(u8, &rb.stage, 0xA5));
    try testing.expectEqual(@as(?usize, null), std.mem.findScalar(u8, &rb.rd_buf, 0xA5));
    try testing.expectEqual(@as(usize, 0), rb.mem.len);
    try testing.expectEqual(@as(usize, 0), rb.mem_len);
    try testing.expect(!rb.spooled());
    try testing.expectEqual(@as(u32, 1), ms.releases);
    rb.deinit(); // a second deinit frees nothing again and releases nothing again
    try testing.expectEqual(@as(u32, 1), ms.releases);
}

test "RewindableBody: a reader() taken mid-body restarts at byte 0 (memory part and spool part)" {
    var body: [5000]u8 = undefined;
    pattern(&body, 17);
    var ms: MemSpool = .{ .gpa = testing.allocator };
    defer ms.deinit();
    var src: Reader = .fixed(&body);
    var rb: RewindableBody = undefined;
    rb.init(testing.allocator, .{ .memory_limit = 700, .spool = ms.source() });
    defer rb.deinit();
    try rb.fill(&src);
    inline for (.{ 100, 700, 900, 4999 }) |partial| {
        var head: [partial]u8 = undefined;
        try rb.reader().readSliceAll(&head);
        try testing.expectEqualSlices(u8, body[0..partial], &head);
        const got = try readAllInto(rb.reader(), testing.allocator);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &body, got);
    }
}

test "RewindableBody: stream never writes more than the limit it was given (memory part and spool part)" {
    var body: [5000]u8 = undefined;
    pattern(&body, 19);
    var ms: MemSpool = .{ .gpa = testing.allocator };
    defer ms.deinit();
    var src: Reader = .fixed(&body);
    var rb: RewindableBody = undefined;
    rb.init(testing.allocator, .{ .memory_limit = 700, .spool = ms.source() });
    defer rb.deinit();
    try rb.fill(&src);
    const r = rb.reader();
    var out: [64]u8 = undefined;
    var at: usize = 0;
    var guard: usize = 0;
    while (at < body.len) : (guard += 1) {
        try testing.expect(guard < 2000);
        var w: Writer = .fixed(&out);
        const n = try RewindableBody.stream(r, &w, .limited(10));
        try testing.expect(n >= 1 and n <= 10);
        try testing.expectEqual(n, w.end);
        try testing.expectEqualSlices(u8, body[at..][0..n], out[0..n]);
        at += n;
    }
    var w: Writer = .fixed(&out);
    try testing.expectError(error.EndOfStream, RewindableBody.stream(r, &w, .limited(10)));
}

test "RewindableBody: a spool read failure stays latched until the next rewind, and a lying or over-long spool is not trusted" {
    var body: [3000]u8 = undefined;
    pattern(&body, 23);
    var ms: MemSpool = .{ .gpa = testing.allocator };
    defer ms.deinit();
    var src: Reader = .fixed(&body);
    var rb: RewindableBody = undefined;
    rb.init(testing.allocator, .{ .memory_limit = 256, .spool = ms.source() });
    defer rb.deinit();
    try rb.fill(&src);
    var out: [8192]u8 = undefined;
    {
        // Latch: the spool recovers, but this reader stays failed.
        const r = rb.reader();
        ms.fail_read = true;
        var w: Writer = .fixed(&out);
        _ = try RewindableBody.stream(r, &w, .unlimited); // the memory part still reads
        try testing.expectError(error.ReadFailed, RewindableBody.stream(r, &w, .unlimited));
        ms.fail_read = false;
        try testing.expectError(error.ReadFailed, RewindableBody.stream(r, &w, .unlimited));
    }
    {
        // A spool reporting more than it was asked for is a read failure.
        ms.lie = true;
        const got = readAllInto(rb.reader(), testing.allocator);
        if (got) |bytes| testing.allocator.free(bytes) else |e| try testing.expectEqual(error.ReadFailed, e);
        try testing.expect(std.meta.isError(got));
        ms.lie = false;
    }
    {
        // A spool that comes up short (0 bytes where the body continues) fails the same way, and also latches.
        const keep = ms.data.items.len;
        const tail = try testing.allocator.dupe(u8, ms.data.items[keep - 1000 ..]);
        defer testing.allocator.free(tail);
        ms.data.shrinkRetainingCapacity(keep - 1000);
        const r = rb.reader();
        var w: Writer = .fixed(&out);
        _ = try RewindableBody.stream(r, &w, .unlimited);
        _ = try RewindableBody.stream(r, &w, .unlimited); // the part that is still there
        try testing.expectError(error.ReadFailed, RewindableBody.stream(r, &w, .unlimited));
        try ms.data.appendSlice(testing.allocator, tail);
        try testing.expectError(error.ReadFailed, RewindableBody.stream(r, &w, .unlimited));
    }
    {
        // The same latch after a lying spool.
        ms.lie = true;
        const r = rb.reader();
        var w: Writer = .fixed(&out);
        _ = try RewindableBody.stream(r, &w, .unlimited);
        try testing.expectError(error.ReadFailed, RewindableBody.stream(r, &w, .unlimited));
        ms.lie = false;
        try testing.expectError(error.ReadFailed, RewindableBody.stream(r, &w, .unlimited));
    }
    {
        // Bytes in the spool beyond the body's length are never exposed.
        try ms.data.appendSlice(testing.allocator, "EXTRA-EXTRA-EXTRA");
        const got = try readAllInto(rb.reader(), testing.allocator);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &body, got);
    }
}

test "FileSpool: readAt never reads past what this spool appended, even over a file that already holds bytes" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "dirty.bin", .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, "0123456789ABCDEFGHIJ", 0);
    var fs = FileSpool.init(io, file);
    const sp = fs.spool();
    try sp.vtable.append(sp.ctx, "xyz");
    var buf: [64]u8 = undefined;
    const n = try sp.vtable.readAt(sp.ctx, 1, &buf);
    try testing.expectEqualStrings("yz", buf[0..n]);
    try testing.expectEqual(@as(usize, 0), try sp.vtable.readAt(sp.ctx, 3, &buf));
}

test "FileSpool: one FileSpool reused for two bodies in a row starts the second at offset 0" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "reuse.bin", .{ .read = true, .truncate = true });
    defer file.close(io);
    var fs = FileSpool.init(io, file);
    const Src = struct {
        sp: *FileSpool,
        fn open(ctx: ?*anyopaque) error{ SpoolOpenFailed, OutOfMemory }!BodySpool {
            const s: *@This() = @ptrCast(@alignCast(ctx.?));
            return s.sp.spool();
        }
    };
    var s: Src = .{ .sp = &fs };
    inline for (.{ 11, 29 }) |seed| {
        var body: [6000]u8 = undefined;
        pattern(&body, seed);
        var src: Reader = .fixed(&body);
        var rb: RewindableBody = undefined;
        rb.init(testing.allocator, .{ .memory_limit = 1000, .spool = .{ .ctx = &s, .open = Src.open } });
        try rb.fill(&src);
        try testing.expectEqual(@as(u64, 5000), fs.len);
        const got = try readAllInto(rb.reader(), testing.allocator);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &body, got);
        rb.deinit();
        try testing.expectEqual(@as(u64, 0), fs.len);
        try testing.expectEqual(@as(u64, 0), try file.length(io));
    }
}

test "FileSpool: a file the caller opened without the right mode is SpoolReadFailed / SpoolWriteFailed, not a panic or an empty read" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const f = try tmp.dir.createFile(io, "wo.bin", .{ .read = false, .truncate = true });
        defer f.close(io);
        var fs = FileSpool.init(io, f);
        const sp = fs.spool();
        try sp.vtable.append(sp.ctx, "abcdef");
        var buf: [8]u8 = undefined;
        try testing.expectError(error.SpoolReadFailed, sp.vtable.readAt(sp.ctx, 0, &buf));
    }
    {
        const f = try tmp.dir.openFile(io, "wo.bin", .{ .mode = .read_only });
        defer f.close(io);
        var fs = FileSpool.init(io, f);
        const sp = fs.spool();
        try testing.expectError(error.SpoolWriteFailed, sp.vtable.append(sp.ctx, "x"));
        try testing.expectEqual(@as(u64, 0), fs.len);
    }
}

test "FileSpool.create: deinit closes the file descriptor (the next open reuses its number)" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const a = try tmp.dir.createFile(io, "a.bin", .{ .read = true, .truncate = true });
    const handle = a.handle;
    const fs = try FileSpool.create(testing.allocator, io, a);
    fs.spool().vtable.deinit(fs.spool().ctx);
    const b = try tmp.dir.createFile(io, "b.bin", .{ .read = true, .truncate = true });
    defer b.close(io);
    try testing.expectEqual(handle, b.handle);
}
