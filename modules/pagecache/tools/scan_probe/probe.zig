// SPDX-License-Identifier: MIT
//! Scan-resistance probe, pagecache side. See README.md in this directory.
//!
//! Workload (identical to `sqlite_side.py`): a file of N pages, a cache of C
//! pages (C << N), a hot set of H < C pages read `passes` times, then ONE
//! sequential scan of all N pages, then the hot set again. Printed: the number
//! of reads that reached the backing store in each phase.

const std = @import("std");
const pagecache = @import("pagecache");
const kvtree = @import("kvtree");

const Storage = pagecache.Storage;
const page_size = pagecache.default_page_size;

/// Forwarding `Storage` that counts the reads that reach the backing store.
const Counting = struct {
    inner: Storage,
    preads: u64 = 0,

    fn cast(ctx: *anyopaque) *Counting {
        return @ptrCast(@alignCast(ctx));
    }
    fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        return cast(ctx).inner.open(path, mode);
    }
    fn vSize(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        return cast(ctx).inner.size(h);
    }
    fn vPread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        const self = cast(ctx);
        self.preads += 1;
        return self.inner.pread(h, buf, off);
    }
    fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        return cast(ctx).inner.writeAll(h, bytes, off);
    }
    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        return cast(ctx).inner.sync(h);
    }
    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        return cast(ctx).inner.truncate(h, len);
    }
    fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
        cast(ctx).inner.close(h);
    }
    fn vRename(ctx: *anyopaque, a: []const u8, b: []const u8) Storage.Error!void {
        return cast(ctx).inner.rename(a, b);
    }
    fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        return cast(ctx).inner.delete(path);
    }
    fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
        return cast(ctx).inner.syncDir();
    }
    fn vTryLock(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return cast(ctx).inner.tryLockExclusive(h);
    }
    const vtable = Storage.VTable{
        .open = vOpen,
        .size = vSize,
        .pread = vPread,
        .writeAll = vWriteAll,
        .sync = vSync,
        .truncate = vTruncate,
        .close = vClose,
        .rename = vRename,
        .delete = vDelete,
        .syncDir = vSyncDir,
        .tryLockExclusive = vTryLock,
    };
    fn storage(self: *Counting) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

const Config = struct { n: usize, c: usize, h: usize, passes: usize };

fn readPage(st: Storage, h: Storage.Handle, buf: []u8, i: usize) !void {
    const got = try st.pread(h, buf, @as(u64, i) * page_size);
    if (got != page_size) return error.ShortRead;
    // Page i was written filled with (i & 0xff): a wrong page would be caught here.
    if (buf[0] != @as(u8, @truncate(i)) or buf[page_size - 1] != @as(u8, @truncate(i))) return error.WrongBytes;
}

fn run(gpa: std.mem.Allocator, cfg: Config) !void {
    var sim = kvtree.SimStorage.init(gpa);
    defer sim.deinit();
    var counting: Counting = .{ .inner = sim.storage() };
    var pc = pagecache.PageCache.init(gpa, counting.storage(), .{ .max_pages = cfg.c });
    defer pc.deinit();
    const st = pc.storage();

    // Build the file straight on the backing store (the cache stays cold).
    const hw = try counting.storage().open("scan.dat", .create_truncate);
    const buf = try gpa.alloc(u8, page_size);
    defer gpa.free(buf);
    for (0..cfg.n) |i| {
        @memset(buf, @as(u8, @truncate(i)));
        try counting.storage().writeAll(hw, buf, @as(u64, i) * page_size);
    }
    try counting.storage().sync(hw);
    counting.storage().close(hw);

    const h = try st.open("scan.dat", .open_or_create);
    defer st.close(h);

    // Phase 1: warm the hot set (pages 0..H-1, spread by a stride so they are
    // not adjacent, `passes` times).
    for (0..cfg.passes) |_| for (0..cfg.h) |k| try readPage(st, h, buf, k * (cfg.n / cfg.h));
    const warm = counting.preads;
    // Phase 2: ONE sequential scan of the whole file.
    counting.preads = 0;
    for (0..cfg.n) |i| try readPage(st, h, buf, i);
    const scan = counting.preads;
    // Phase 3: the hot set again, once. Every backend read here is a hot page
    // the scan pushed out.
    counting.preads = 0;
    for (0..cfg.h) |k| try readPage(st, h, buf, k * (cfg.n / cfg.h));
    const after = counting.preads;
    const s = pc.stats();
    std.debug.print(
        "pagecache  N={d} C={d} H={d} passes={d}  backend reads: warm={d} scan={d} hot-again={d}  (resident={d})\n",
        .{ cfg.n, cfg.c, cfg.h, cfg.passes, warm, scan, after, s.resident_pages },
    );
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const configs = [_]Config{
        .{ .n = 2000, .c = 200, .h = 100, .passes = 10 },
        .{ .n = 2000, .c = 200, .h = 100, .passes = 2 },
        .{ .n = 2000, .c = 200, .h = 180, .passes = 10 },
    };
    for (configs) |cfg| try run(gpa, cfg);
}
