// SPDX-License-Identifier: MIT
//! Crash-consistency and hostile-store tests for blobstore (grade-2 round,
//! 2026-11-03).
//!
//! * Crash injection: every write sequence is interrupted after each of its
//!   steps (`root.crash_hook`), the directory is left exactly as a process
//!   killed there would have left it, and the invariants are checked on that
//!   state and again after a restart that retries the operation and runs `gc`.
//!   What this does NOT show: that `fsync` really orders the writes on a given
//!   disk (no power is cut). It shows that no PREFIX of the sequence leaves a
//!   torn blob, a torn sidecar, an under-counted reference or unreclaimable
//!   debris.
//! * Hostile store: FIFOs, symlinks and directories planted at the paths the
//!   store reads (and at the deterministic temp names it writes) must be
//!   refused or replaced, never block.
//! * Model: a seeded random sequence of operations compared with an in-memory
//!   reference model of the documented semantics.
const std = @import("std");
const t = std.testing;
const linux = std.os.linux;
const root = @import("root.zig");
const Store = root.Store;
const Digest = root.Digest;

fn tmpBase(tmp: *std.testing.TmpDir, buf: []u8) ![]const u8 {
    return std.mem.print(buf, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
}

fn digestOf(bytes: []const u8) Digest {
    return .{ .hex = @import("hashdigest").sha256HexBuf(bytes) };
}

fn mkfifo(path: []const u8) !void {
    var pz: [900]u8 = undefined;
    const z = try std.mem.printSentinel(&pz, "{s}", .{path}, 0);
    const rc = linux.mknodat(linux.AT.FDCWD, z, linux.S.IFIFO | 0o600, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
}

// ── crash injection ─────────────────────────────────────────────────────────

const blob_a = "alpha blob, already stored before the crash";
const blob_b = "beta blob, being stored when the crash comes";

/// Every non-hidden file under `cas/` is `<hex>` or `<hex>.rc` with a numeric
/// body; every hex file hashes to its name. Returns the number of hidden debris
/// files seen.
fn checkCas(store: Store, strict_rc: bool) !usize {
    var dbuf: [512]u8 = undefined;
    const casdir = try std.mem.print(&dbuf, "{s}/cas", .{store.base});
    var dir = std.Io.Dir.cwd().openDir(t.io, casdir, .{ .iterate = true }) catch return 0;
    defer dir.close(t.io);
    var walker = try dir.walk(t.allocator);
    defer walker.deinit();
    var debris: usize = 0;
    while (try walker.next(t.io)) |e| {
        if (e.kind != .file) continue;
        if (e.basename[0] == '.') {
            debris += 1;
            continue;
        }
        if (std.mem.endsWith(u8, e.basename, ".rc")) {
            var vb: [64]u8 = undefined;
            const body = try dir.readFile(t.io, e.path, &vb);
            if (strict_rc) _ = try std.fmt.parseInt(u64, body, 10); // never torn, never empty
            continue;
        }
        const d = try Digest.fromHex(e.basename);
        try t.expect(try store.verify(d)); // never a torn or foreign blob
    }
    return debris;
}

const CrashOp = enum { put_new, put_dup, delete_last, delete_shared, put_named, raw_commit };

fn setup(store: Store, op: CrashOp) !void {
    switch (op) {
        .put_new => {},
        .put_dup => _ = try store.putBytes(blob_a),
        .delete_last => _ = try store.putBytes(blob_a),
        .delete_shared => {
            _ = try store.putBytes(blob_a);
            _ = try store.putBytes(blob_a);
        },
        .put_named => try store.putNamed("ns", "rec", "old record"),
        .raw_commit => {
            var tb: [768]u8 = undefined;
            const tf = try store.createTemp("ns", "k", &tb);
            try tf.file.writeStreamingAll(t.io, "old raw");
            tf.file.close(t.io);
            try store.commit("ns", "k", tf.tmp);
        },
    }
}

fn run(store: Store, op: CrashOp) !void {
    switch (op) {
        .put_new => _ = try store.putBytes(blob_b),
        .put_dup => _ = try store.putBytes(blob_a),
        .delete_last, .delete_shared => _ = try store.delete(digestOf(blob_a)),
        .put_named => try store.putNamed("ns", "rec", "new record!"),
        .raw_commit => {
            var tb: [768]u8 = undefined;
            const tf = try store.createTemp("ns", "k", &tb);
            try tf.file.writeStreamingAll(t.io, "new raw!");
            tf.file.close(t.io);
            try store.commit("ns", "k", tf.tmp);
        },
    }
}

fn readAll(f: std.Io.File, buf: []u8) ![]u8 {
    var r = f.reader(t.io, &.{});
    const n = try r.interface.readSliceShort(buf);
    return buf[0..n];
}

/// What the state must satisfy after a crash at any point of `op`.
fn checkAfterCrash(store: Store, op: CrashOp) !void {
    _ = try checkCas(store, true);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const a = digestOf(blob_a);
    const b = digestOf(blob_b);
    switch (op) {
        .put_new => {
            // absent, or present whole with at least one reference (never 0)
            if (store.has(b)) {
                try t.expect(try store.verify(b));
                const rc = (try store.refcountOf(b)).?;
                try t.expect(rc >= 1 and rc <= 1);
            }
        },
        .put_dup => {
            try t.expect(try store.verify(a));
            const rc = (try store.refcountOf(a)).?;
            try t.expect(rc == 1 or rc == 2); // never under-counted
        },
        .delete_last => {
            try t.expect(try store.verify(a));
            const rc = (try store.refcountOf(a)).?;
            try t.expect(rc == 0 or rc == 1);
        },
        .delete_shared => {
            const rc = (try store.refcountOf(a)).?;
            try t.expect(rc == 1 or rc == 2);
        },
        .put_named => {
            const got = (try store.readNamed(arena, "ns", "rec")).?;
            try t.expect(std.mem.eql(u8, got, "old record") or std.mem.eql(u8, got, "new record!"));
        },
        .raw_commit => {
            const f = (try store.openBlob("ns", "k")).?;
            defer f.close(t.io);
            var rb: [32]u8 = undefined;
            const got = try readAll(f, &rb);
            try t.expect(std.mem.eql(u8, got, "old raw") or std.mem.eql(u8, got, "new raw!"));
        },
    }
}

/// After the "restart": the retry succeeds, the final state is the one the
/// operation promises, and `gc` leaves no debris.
fn checkAfterRetry(store: Store, op: CrashOp) !void {
    try run(store, op);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const a = digestOf(blob_a);
    const b = digestOf(blob_b);
    switch (op) {
        .put_new => {
            try t.expect(try store.verify(b));
            const rc = (try store.refcountOf(b)).?;
            try t.expect(rc == 1 or rc == 2); // 2 = the crash had already named the blob
        },
        .put_dup => try t.expect((try store.refcountOf(a)).? >= 2),
        .delete_last => try t.expectEqual(@as(u64, 0), (try store.refcountOf(a)).?),
        .delete_shared => try t.expect((try store.refcountOf(a)).? <= 1),
        .put_named => try t.expectEqualStrings("new record!", (try store.readNamed(arena, "ns", "rec")).?),
        .raw_commit => {
            const f = (try store.openBlob("ns", "k")).?;
            defer f.close(t.io);
            var rb: [32]u8 = undefined;
            try t.expectEqualStrings("new raw!", try readAll(f, &rb));
        },
    }
    _ = try store.gc(t.allocator, &.{}, .{ .stale_after_ns = 1 });
    // gc reaps ingest temps; the one deterministic sidecar temp is reused, so
    // after a retry that rewrote the sidecar none is left either
    try t.expectEqual(@as(usize, 0), try checkCas(store, true));
}

fn crashSweep(op: CrashOp) !void {
    // How many injection points does the operation have?
    var points: u32 = 0;
    {
        var tmp = t.tmpDir(.{});
        defer tmp.cleanup();
        var bb: [256]u8 = undefined;
        const store = try Store.init(t.io, try tmpBase(&tmp, &bb));
        try setup(store, op);
        root.crash_hook.arm(std.math.maxInt(u32)); // armed but never reached: counts
        defer root.crash_hook.arm(null);
        try run(store, op);
        points = root.crash_hook.tick;
    }
    try t.expect(points >= 3); // "all ok over zero points" is not ok
    var k: u32 = 0;
    while (k < points) : (k += 1) {
        var tmp = t.tmpDir(.{});
        defer tmp.cleanup();
        var bb: [256]u8 = undefined;
        const store = try Store.init(t.io, try tmpBase(&tmp, &bb));
        try setup(store, op);
        root.crash_hook.arm(k);
        const r = run(store, op);
        const tripped = root.crash_hook.tripped;
        root.crash_hook.arm(null);
        try t.expect(tripped); // the k-th point was reached and fired
        try t.expectError(error.SimulatedCrash, r);
        try checkAfterCrash(store, op);
        // a restarted process: a fresh Store value over the same directory
        const again = try Store.init(t.io, store.base);
        try checkAfterRetry(again, op);
    }
}

test "crash: put of a new blob, interrupted after every step" {
    try crashSweep(.put_new);
}

test "crash: put of an existing blob (dedup, refcount bump), interrupted after every step" {
    try crashSweep(.put_dup);
}

test "crash: delete of the last reference, interrupted after every step" {
    try crashSweep(.delete_last);
}

test "crash: delete of a shared blob, interrupted after every step" {
    try crashSweep(.delete_shared);
}

test "crash: putNamed overwrite, interrupted after every step" {
    try crashSweep(.put_named);
}

test "crash: raw commit over an existing key, interrupted after every step" {
    try crashSweep(.raw_commit);
}

test "crash: a stale rc temp from a crash is reused, not accumulated" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try Store.init(t.io, try tmpBase(&tmp, &bb));
    _ = try store.putBytes(blob_a);
    // crash during every sidecar rewrite, many times: one temp, not many
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        root.crash_hook.arm(2); // inside the sidecar rewrite (0, 1 are the ingest)
        _ = store.putBytes(blob_a) catch {};
        root.crash_hook.arm(null);
    }
    try t.expectEqual(@as(usize, 1), try checkCas(store, true)); // exactly one rc temp, reused
}

// ── hostile store ───────────────────────────────────────────────────────────

fn plant(store: Store, hex: []const u8, suffix: []const u8, comptime kind: enum { fifo, dir, zero_link }) !void {
    // make the fan-out directory by storing something that lands in it first
    var pb: [768]u8 = undefined;
    const cas = try store.casPath(&pb, hex);
    const dirp = std.fs.path.dirname(cas).?;
    std.Io.Dir.cwd().createDirPath(t.io, dirp) catch {};
    var fb: [800]u8 = undefined;
    const path = try std.mem.print(&fb, "{s}{s}", .{ cas, suffix });
    switch (kind) {
        .fifo => try mkfifo(path),
        .dir => try std.Io.Dir.cwd().createDirPath(t.io, path),
        .zero_link => std.Io.Dir.cwd().symLink(t.io, "/dev/zero", path, .{}) catch return error.SkipZigTest,
    }
}

test "hostile store: a FIFO, directory or /dev/zero symlink at a blob path is refused, never opened" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    _ = try Store.init(t.io, try tmpBase(&tmp, &bb));
    const d = digestOf("planted");
    inline for (.{ .fifo, .dir, .zero_link }) |kind| {
        var sub = t.tmpDir(.{});
        defer sub.cleanup();
        var b2: [256]u8 = undefined;
        const s = try Store.init(t.io, try tmpBase(&sub, &b2));
        try plant(s, d.slice(), "", kind);
        try t.expect(!s.has(d)); // not a dedup hit
        try t.expectError(error.NotRegularFile, s.open(d));
        try t.expectError(error.NotRegularFile, s.verify(d));
        // put of the same content replaces a FIFO or link; a directory stays an error
        if (kind == .dir) {
            if (s.putBytes("planted")) |_| return error.TestUnexpectedResult else |_| {}
        } else {
            const got = try s.putBytes("planted");
            try t.expectEqualSlices(u8, d.slice(), got.slice());
            try t.expect(try s.verify(d));
        }
    }
}

test "hostile store: a FIFO or directory as the refcount sidecar does not block put, delete or gc" {
    inline for (.{ .fifo, .dir }) |kind| {
        var tmp = t.tmpDir(.{});
        defer tmp.cleanup();
        var bb: [256]u8 = undefined;
        const store = try Store.init(t.io, try tmpBase(&tmp, &bb));
        const d = try store.putBytes("with a bad sidecar");
        // replace the real sidecar by the hostile thing
        var pb: [768]u8 = undefined;
        const cas = try store.casPath(&pb, d.slice());
        var rb: [800]u8 = undefined;
        const rc = try std.mem.print(&rb, "{s}.rc", .{cas});
        try std.Io.Dir.cwd().deleteFile(t.io, rc);
        try plant(store, d.slice(), ".rc", kind);
        // reads fall back to the implicit single reference; gc keeps the blob
        try t.expectEqual(@as(?u64, 1), try store.refcountOf(d));
        const st = try store.gc(t.allocator, &.{}, .{});
        try t.expectEqual(@as(u64, 0), st.blobs_removed);
        try t.expect(store.has(d));
        if (kind == .fifo) {
            // a FIFO sidecar is replaced by the next write
            _ = try store.putBytes("with a bad sidecar");
            try t.expectEqual(@as(?u64, 2), try store.refcountOf(d));
        }
    }
}

test "hostile store: a FIFO at the deterministic temp names does not block the writers" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try Store.init(t.io, try tmpBase(&tmp, &bb));
    const d = try store.putBytes("first");
    // the sidecar temp `.<hex>.rc.tmp`
    var pb: [768]u8 = undefined;
    const cas = try store.casPath(&pb, d.slice());
    const dirp = std.fs.path.dirname(cas).?;
    var fb: [900]u8 = undefined;
    try mkfifo(try std.mem.print(&fb, "{s}/.{s}.rc.tmp", .{ dirp, d.slice() }));
    _ = try store.putBytes("first"); // dedup bump writes the sidecar through that temp
    try t.expectEqual(@as(?u64, 2), try store.refcountOf(d));
    // the raw layer's `.<key>.part`
    var tb: [768]u8 = undefined;
    const first = try store.createTemp("ns", "k", &tb);
    first.file.close(t.io);
    store.discardTemp(first.tmp);
    try mkfifo(first.tmp);
    const second = try store.createTemp("ns", "k", &tb);
    second.file.close(t.io);
    store.discardTemp(second.tmp);
    // scratch
    var sb: [768]u8 = undefined;
    const sc = try store.scratchCreate("scr", &sb);
    sc.file.close(t.io);
    store.discardTemp(sc.path);
    try mkfifo(sc.path);
    const sc2 = try store.scratchCreate("scr", &sb);
    sc2.file.close(t.io);
    store.discardTemp(sc2.path);
}

test "hostile store: a FIFO or symlink as a named record or raw blob is refused" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try Store.init(t.io, try tmpBase(&tmp, &bb));
    try store.putNamed("ns", "ok", "fine");
    var pb: [768]u8 = undefined;
    const nd = try std.mem.print(&pb, "{s}/named/ns/fifo", .{store.base});
    try mkfifo(nd);
    var lb: [768]u8 = undefined;
    const ln = try std.mem.print(&lb, "{s}/named/ns/zero", .{store.base});
    std.Io.Dir.cwd().symLink(t.io, "/dev/zero", ln, .{}) catch return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try t.expectError(error.NotRegularFile, store.readNamed(arena, "ns", "fifo"));
    try t.expectError(error.NotRegularFile, store.readNamed(arena, "ns", "zero"));
    try t.expectEqualStrings("fine", (try store.readNamed(arena, "ns", "ok")).?);
    // the listings and the iterator skip what is not a regular file
    const keys = try store.listNamed(arena, "ns");
    try t.expectEqual(@as(usize, 1), keys.len);
    var it = try store.names(.named, "ns");
    defer it.deinit();
    var seen: usize = 0;
    while (try it.next()) |e| {
        try t.expectEqualStrings("ok", e.key);
        seen += 1;
    }
    try t.expectEqual(@as(usize, 1), seen);
}

test "putLimited: an endless stream is StreamTooLong and leaves nothing behind" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try Store.init(t.io, try tmpBase(&tmp, &bb));
    var zero = std.Io.Dir.cwd().openFile(t.io, "/dev/zero", .{}) catch return error.SkipZigTest;
    defer zero.close(t.io);
    var rbuf: [4096]u8 = undefined;
    var fr = std.Io.File.Reader.initStreaming(zero, t.io, &rbuf);
    try t.expectError(error.StreamTooLong, store.putLimited(&fr.interface, 1 << 20));
    try t.expectEqual(@as(usize, 0), try checkCas(store, true)); // no temp left
    // exactly at the limit is accepted, one over is not
    var r1: std.Io.Reader = .fixed("12345678");
    _ = try store.putLimited(&r1, 8);
    var r2: std.Io.Reader = .fixed("123456789");
    try t.expectError(error.StreamTooLong, store.putLimited(&r2, 8));
    var r3: std.Io.Reader = .fixed("x");
    try t.expectError(error.StreamTooLong, store.putLimited(&r3, 0));
    var r4: std.Io.Reader = .fixed("");
    _ = try store.putLimited(&r4, 0); // the empty blob fits a zero limit
}

test "names: pages through a namespace in bounded memory, skipping temps" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try Store.init(t.io, try tmpBase(&tmp, &bb));
    var it0 = try store.names(.raw, "absent");
    defer it0.deinit();
    try t.expect((try it0.next()) == null);
    try t.expectError(error.InvalidName, store.names(.raw, "../x"));
    var i: usize = 0;
    var tb: [768]u8 = undefined;
    var kb: [32]u8 = undefined;
    while (i < 40) : (i += 1) {
        const key = try std.mem.print(&kb, "k{d}", .{i});
        const tf = try store.createTemp("ns", key, &tb);
        try tf.file.writeStreamingAll(t.io, "abc");
        tf.file.close(t.io);
        try store.commit("ns", key, tf.tmp);
    }
    const pending = try store.createTemp("ns", "pending", &tb); // a hidden .part: not listed
    pending.file.close(t.io);
    var it = try store.names(.raw, "ns");
    defer it.deinit();
    var n: usize = 0;
    var bytes: u64 = 0;
    while (try it.next()) |e| {
        n += 1;
        bytes += e.bytes;
    }
    try t.expectEqual(@as(usize, 40), n);
    try t.expectEqual(@as(u64, 120), bytes);
}

// ── model ───────────────────────────────────────────────────────────────────

const n_contents = 6;

const Model = struct {
    present: [n_contents]bool = @splat(false),
    rc: [n_contents]u64 = @splat(0),
};

fn content(i: usize, buf: []u8) []const u8 {
    // distinct, a few sizes (one empty, one spanning two 64 KiB chunks)
    const sizes = [n_contents]usize{ 0, 1, 100, 4096, 70_000, 200_000 };
    const n = sizes[i];
    for (buf[0..n], 0..) |*c, j| c.* = @truncate(j *% 31 +% i *% 7 +% 1);
    return buf[0..n];
}

fn modelRun(seed: u64, fanout: u8) !void {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    var store = try Store.initOptions(t.io, try tmpBase(&tmp, &bb), .{ .fanout = fanout });
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    var m: Model = .{};
    const big = try t.allocator.alloc(u8, 200_000);
    defer t.allocator.free(big);
    var digests: [n_contents]Digest = undefined;
    for (&digests, 0..) |*d, i| d.* = digestOf(content(i, big));

    var step: usize = 0;
    while (step < 250) : (step += 1) {
        const i = rnd.uintLessThan(usize, n_contents);
        switch (rnd.uintLessThan(u8, 8)) {
            0, 1, 2 => { // put
                const bytes = content(i, big);
                const got = try store.putBytes(bytes);
                try t.expectEqualSlices(u8, digests[i].slice(), got.slice());
                m.rc[i] = if (m.present[i]) m.rc[i] +| 1 else 1;
                m.present[i] = true;
            },
            3 => { // delete
                const bytes = content(i, big);
                _ = bytes;
                const r = try store.delete(digests[i]);
                try t.expectEqual(m.present[i], r);
                if (m.present[i] and m.rc[i] > 0) m.rc[i] -= 1;
            },
            4 => { // gc with a random keep set
                var keep_buf: [n_contents]Digest = undefined;
                var keep_n: usize = 0;
                var kept: [n_contents]bool = @splat(false);
                for (0..n_contents) |j| if (rnd.boolean() and rnd.boolean()) {
                    keep_buf[keep_n] = digests[j];
                    keep_n += 1;
                    kept[j] = true;
                };
                var removed: u64 = 0;
                var reclaimed: u64 = 0;
                const sizes = [n_contents]u64{ 0, 1, 100, 4096, 70_000, 200_000 };
                for (0..n_contents) |j| {
                    if (m.present[j] and m.rc[j] == 0 and !kept[j]) {
                        m.present[j] = false;
                        removed += 1;
                        reclaimed += sizes[j];
                    }
                }
                const st = try store.gc(t.allocator, keep_buf[0..keep_n], .{});
                try t.expectEqual(removed, st.blobs_removed);
                try t.expectEqual(reclaimed, st.bytes_reclaimed);
            },
            5 => { // a hostile sidecar: garbage reads as the one implicit reference
                if (m.present[i]) {
                    var pb: [768]u8 = undefined;
                    const cas = try store.casPath(&pb, digests[i].slice());
                    var rb: [800]u8 = undefined;
                    const rcp = try std.mem.print(&rb, "{s}.rc", .{cas});
                    const garbage = [_][]const u8{ "", "x", "-3", "99999999999999999999999999999", " 7 7" };
                    try std.Io.Dir.cwd().writeFile(t.io, .{ .sub_path = rcp, .data = garbage[rnd.uintLessThan(usize, garbage.len)] });
                    m.rc[i] = 1;
                }
            },
            6 => { // restart: a new Store value over the same directory
                store = try Store.initOptions(t.io, store.base, .{ .fanout = fanout });
            },
            else => { // a bounded put that is too short changes nothing
                const bytes = content(i, big);
                if (bytes.len > 0) {
                    var r: std.Io.Reader = .fixed(bytes);
                    try t.expectError(error.StreamTooLong, store.putLimited(&r, bytes.len - 1));
                }
            },
        }
        // the whole store equals the model after every step
        for (0..n_contents) |j| {
            try t.expectEqual(m.present[j], store.has(digests[j]));
            if (m.present[j]) {
                try t.expectEqual(@as(?u64, m.rc[j]), try store.refcountOf(digests[j]));
                try t.expect(try store.verify(digests[j]));
            } else {
                try t.expectEqual(@as(?u64, null), try store.refcountOf(digests[j]));
                try t.expectError(error.NotFound, store.verify(digests[j]));
            }
        }
    }
    _ = try checkCas(store, false);
}

test "model: 250 random operations match the in-memory reference model (fanout 1..3, 4 seeds each)" {
    for ([_]u8{ 1, 2, 3 }) |fo| {
        for ([_]u64{ 1, 2, 3, 0xfeed }) |seed| try modelRun(seed * 977 + fo, fo);
    }
}
