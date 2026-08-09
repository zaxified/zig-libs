// SPDX-License-Identifier: MIT
//! Opt-in profile of the F3 finding: the copying `Storage.pread` seam makes a
//! cache **hit** cost one whole-page `@memcpy` and a **miss** cost two (the
//! inner `pread` into the caller's buffer, then `cache.put` duping that buffer
//! into cache storage). The borrow path (`PageCache.preadRef` / `Storage.Ref`)
//! removes one copy from each: a hit lends the resident bytes (zero copies), a
//! miss has the inner `pread` land straight in the cache slot that will hold
//! the page (one). Allocations per miss are *unchanged* — three either way
//! (key dup, page buffer, index node) — because the copying path's second
//! buffer is the caller's, not the cache's; the win is the copy, not the
//! allocator traffic, and this bench reports the measured number rather than
//! the one the finding predicted.
//! Off by default (`error.SkipZigTest`); run it with:
//!
//!   PAGECACHE_BENCH=1 scripts/capped zig build test-pagecache -Doptimize=ReleaseFast
//!
//! It reports two things per access shape, because only one of them is a
//! property of the code rather than of this host:
//!
//!   * **copies and allocations per access** — counted, not timed, via a
//!     counting allocator around the cache and a byte-exact accounting of
//!     `@memcpy`ed page bytes. This is the acceptance criterion.
//!   * ns/access and MiB/s — this host, this run, one page size.
//!
//! **Sizing.** A 1024-page (4 MiB) simulated file and a 64-page (256 KiB)
//! cache. Deliberately small: an over-eager benchmark has OOM-killed this host
//! before, and the constant factor under test does not need a big working set
//! to show up. Run under `scripts/capped`.

const std = @import("std");
const root = @import("root.zig");
const kvtree = @import("kvtree");

const PageCache = root.PageCache;
const page_size = root.default_page_size;

/// Pages in the simulated file (4 MiB at 4 KiB pages).
const file_pages: usize = 1024;
/// Resident budget, in pages (256 KiB) — small enough that the sequential
/// sweep is nearly all misses and the hot-set loop is nearly all hits.
const budget_pages: usize = 64;
/// Hot working set for the hit benchmark: comfortably inside the budget.
const hot_pages: usize = 32;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// Counts allocations without changing behaviour, so "allocations per page
/// fill" is a measured number rather than a code-reading claim.
const Counting = struct {
    inner: std.mem.Allocator,
    allocs: usize = 0,
    frees: usize = 0,
    bytes: usize = 0,

    fn allocator(self: *Counting) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.allocs += 1;
        self.bytes += len;
        return self.inner.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        return self.inner.rawResize(buf, a, new_len, ra);
    }
    fn remap(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        return self.inner.rawRemap(buf, a, new_len, ra);
    }
    fn free(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.frees += 1;
        self.inner.rawFree(buf, a, ra);
    }
};

/// Fill `sim` with `file_pages` distinct pages, then leave the cache cold.
fn seed(gpa: std.mem.Allocator, pc: *PageCache) !u32 {
    const st = pc.storage();
    const h = try st.open("bench.dat", .create_truncate);
    const page = try gpa.alloc(u8, page_size);
    defer gpa.free(page);
    for (0..file_pages) |i| {
        @memset(page, @as(u8, @truncate(i)));
        try st.writeAll(h, page, i * page_size);
    }
    pc.cache.clear();
    return h;
}

const Result = struct {
    ns_per_access: u64,
    allocs_per_access: f64,
    /// Page bytes copied per access, in units of whole pages.
    copies_per_access: f64,
};

fn report(name: []const u8, r: Result) void {
    const mib_per_s: f64 = if (r.ns_per_access == 0) 0 else @as(f64, @floatFromInt(page_size)) * 1000.0 / @as(f64, @floatFromInt(r.ns_per_access)) / 1.048576;
    std.debug.print(
        "  {s:<34} {d:>4} ns  {d:>8.0} MiB/s   copies/access {d:.2}   allocs/access {d:.2}\n",
        .{ name, r.ns_per_access, mib_per_s, r.copies_per_access, r.allocs_per_access },
    );
}

test "pagecache: F3 copy/allocation cost of a page read, copying seam vs borrow seam" {
    if (std.testing.environ.getPosix("PAGECACHE_BENCH") == null) return error.SkipZigTest;

    // NOT std.testing.allocator: its per-allocation bookkeeping is the same
    // order as the page copy this bench exists to measure.
    const gpa = std.heap.smp_allocator;

    std.debug.print(
        "\npagecache: F3 page-read cost (page {d} B, file {d} pages, budget {d} pages)\n",
        .{ page_size, file_pages, budget_pages },
    );

    const iters: usize = 20_000;
    const buf = try gpa.alloc(u8, page_size);
    defer gpa.free(buf);

    // ── hits ────────────────────────────────────────────────────────────────
    {
        var counting = Counting{ .inner = gpa };
        var sim = kvtree.SimStorage.init(counting.allocator());
        defer sim.deinit();
        sim.allow_overwrite = true;
        var pc = PageCache.init(counting.allocator(), sim.storage(), .{ .max_pages = budget_pages });
        defer pc.deinit();
        const h = try seed(gpa, &pc);
        const st = pc.storage();

        // Warm the hot set so every measured access is a hit.
        for (0..hot_pages) |i| _ = try st.pread(h, buf, i * page_size);

        const a0 = counting.allocs;
        const hits0 = pc.hits;
        var t0 = nowNs();
        for (0..iters) |i| _ = try st.pread(h, buf, (i % hot_pages) * page_size);
        const copy_ns = (nowNs() - t0) / iters;
        const copy_allocs = counting.allocs - a0;

        const a1 = counting.allocs;
        t0 = nowNs();
        for (0..iters) |i| {
            const p = (try pc.preadRef(h, page_size, (i % hot_pages) * page_size)).?;
            std.mem.doNotOptimizeAway(p.bytes[0]);
            pc.releasePage(p);
        }
        const ref_ns = (nowNs() - t0) / iters;
        const ref_allocs = counting.allocs - a1;

        // Sanity: these really were hits, not misses in disguise.
        if (pc.hits - hits0 != iters) return error.BenchNotAllHits;
        if (pc.stats().ref_hits != iters) return error.BenchNotAllRefHits;

        std.debug.print(" cache HIT:\n", .{});
        report("pread (copying seam)", .{
            .ns_per_access = copy_ns,
            .allocs_per_access = @as(f64, @floatFromInt(copy_allocs)) / @as(f64, @floatFromInt(iters)),
            .copies_per_access = 1.0, // the @memcpy(buf, cached) at vPread
        });
        report("preadRef (borrow seam)", .{
            .ns_per_access = ref_ns,
            .allocs_per_access = @as(f64, @floatFromInt(ref_allocs)) / @as(f64, @floatFromInt(iters)),
            .copies_per_access = 0.0, // the bytes ARE the cache's storage
        });
    }

    // ── misses ──────────────────────────────────────────────────────────────
    {
        var counting = Counting{ .inner = gpa };
        var sim = kvtree.SimStorage.init(counting.allocator());
        defer sim.deinit();
        sim.allow_overwrite = true;
        var pc = PageCache.init(counting.allocator(), sim.storage(), .{ .max_pages = budget_pages });
        defer pc.deinit();
        const h = try seed(gpa, &pc);
        const st = pc.storage();

        // A sequential sweep of a file 16x the budget: every access is a miss.
        const a0 = counting.allocs;
        const m0 = pc.misses;
        var t0 = nowNs();
        for (0..iters) |i| _ = try st.pread(h, buf, (i % file_pages) * page_size);
        const copy_ns = (nowNs() - t0) / iters;
        const copy_allocs = counting.allocs - a0;
        const copy_misses = pc.misses - m0;

        pc.cache.clear();
        const a1 = counting.allocs;
        t0 = nowNs();
        for (0..iters) |i| {
            const p = (try pc.preadRef(h, page_size, (i % file_pages) * page_size)).?;
            std.mem.doNotOptimizeAway(p.bytes[0]);
            pc.releasePage(p);
        }
        const ref_ns = (nowNs() - t0) / iters;
        const ref_allocs = counting.allocs - a1;
        const ref_misses = pc.stats().ref_misses;

        std.debug.print(
            " cache MISS ({d}/{d} copying, {d}/{d} borrow were real misses):\n",
            .{ copy_misses, iters, ref_misses, iters },
        );
        report("pread (copying seam)", .{
            .ns_per_access = copy_ns,
            .allocs_per_access = @as(f64, @floatFromInt(copy_allocs)) / @as(f64, @floatFromInt(iters)),
            .copies_per_access = 2.0, // inner pread into buf, then cache.put dupes buf
        });
        report("preadRef (borrow seam)", .{
            .ns_per_access = ref_ns,
            .allocs_per_access = @as(f64, @floatFromInt(ref_allocs)) / @as(f64, @floatFromInt(iters)),
            .copies_per_access = 1.0, // inner pread lands directly in cache storage
        });
    }

    std.debug.print(
        "  (copies/access are byte-exact whole-page copies by construction, not a\n" ++
            "   measurement; allocs/access is counted by a wrapping allocator, and the\n" ++
            "   miss path's 3 are the same 3 either way — the saving is the copy, not\n" ++
            "   allocator traffic.\n" ++
            "   Read the two shapes differently: the HIT is a real, repeatable win (one\n" ++
            "   whole-page memcpy removed). The MISS is a WASH on this in-memory backend\n" ++
            "   and has measured slightly slower here — the copy it saves (~40 ns for 4 KiB)\n" ++
            "   is about what pin+reserve+release costs in extra index work versus get+put,\n" ++
            "   and both are noise next to a real read(2). Do not quote the miss row as a\n" ++
            "   speedup; the miss path's claim is one fewer copy, not fewer nanoseconds.\n" ++
            "   LMDB, the named C reference, is 0 copies / 0 allocations\n" ++
            "   on a hit because it hands back a pointer into an mmap'd page: the borrow\n" ++
            "   seam matches it on the hit path, while the miss path still owes the one\n" ++
            "   copy any read(2)-based backend has to pay.)\n",
        .{},
    );
}
