// SPDX-License-Identifier: MIT

//! Structural hostile inputs: metadata BUILT with `fb.Builder` to cost the reader
//! far more than its size — FlatBuffers tables shared through many offsets (a DAG
//! of fields), one name string behind thousands of fields, many columns whose rows
//! cost no body bytes, compressed bodies of one repeated byte over many batches,
//! dictionary entries copied into many rows, file footer blocks naming one message
//! twice or lying about its lengths. Byte flips and the fuzz driver mutate valid
//! inputs locally and cannot make these. Each runs under a byte-capped allocator:
//! the read must end in its error, never in the cap.

const std = @import("std");
const df = @import("dataframe");
const zstd = @import("zstd");
const fb = @import("fb.zig");
const schema = @import("schema.zig");
const ipc = @import("ipc.zig");
const stream = @import("stream.zig");
const st = @import("stream_test.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;

/// Fails an allocation (null, so `error.OutOfMemory`) once `cap` bytes would be live;
/// records the peak.
const Capped = struct {
    child: Allocator,
    cap: usize,
    used: usize = 0,
    peak: usize = 0,

    fn allocator(c: *Capped) Allocator {
        return .{ .ptr = c, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn grow(c: *Capped, old: usize, new: usize) bool {
        if (new > old and new - old > c.cap - c.used) return false;
        c.used = c.used - old + new;
        c.peak = @max(c.peak, c.used);
        return true;
    }

    fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c: *Capped = @ptrCast(@alignCast(ctx));
        if (len > c.cap - c.used) return null;
        const p = c.child.rawAlloc(len, al, ra) orelse return null;
        _ = c.grow(0, len);
        return p;
    }

    fn resize(ctx: *anyopaque, mem: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const c: *Capped = @ptrCast(@alignCast(ctx));
        if (new_len > mem.len and new_len - mem.len > c.cap - c.used) return false;
        if (!c.child.rawResize(mem, al, new_len, ra)) return false;
        _ = c.grow(mem.len, new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, mem: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const c: *Capped = @ptrCast(@alignCast(ctx));
        if (new_len > mem.len and new_len - mem.len > c.cap - c.used) return null;
        const p = c.child.rawRemap(mem, al, new_len, ra) orelse return null;
        _ = c.grow(mem.len, new_len);
        return p;
    }

    fn free(ctx: *anyopaque, mem: []u8, al: std.mem.Alignment, ra: usize) void {
        const c: *Capped = @ptrCast(@alignCast(ctx));
        c.child.rawFree(mem, al, ra);
        c.used -= mem.len;
    }
};

/// `readStream` under an arena over a `cap`-byte allocator: the error it ends in, and the
/// peak bytes it held.
fn streamUnderCap(bytes: []const u8, opts: stream.ReadOptions, cap: usize) !struct { err: ?anyerror, peak: usize } {
    var capped: Capped = .{ .child = testing.allocator, .cap = cap };
    var arena = std.heap.ArenaAllocator.init(capped.allocator());
    defer arena.deinit();
    const got = stream.readStream(arena.allocator(), bytes, opts);
    return .{ .err = if (got) |_| null else |e| e, .peak = capped.peak };
}

fn fileUnderCap(bytes: []const u8, opts: stream.ReadOptions, cap: usize) !struct { err: ?anyerror, peak: usize } {
    var capped: Capped = .{ .child = testing.allocator, .cap = cap };
    var arena = std.heap.ArenaAllocator.init(capped.allocator());
    defer arena.deinit();
    const got = stream.readFile(arena.allocator(), bytes, opts);
    return .{ .err = if (got) |_| null else |e| e, .peak = capped.peak };
}

/// A stream whose only message is the schema table `fields_vec` (an offset vector already
/// in `b`), then end of stream.
fn schemaOnly(gpa: Allocator, b: *fb.Builder, fields_vec: fb.Ref) ![]u8 {
    b.startTable();
    try b.addOffset(1, fields_vec);
    const sref = try b.endTable();
    b.startTable();
    try b.addScalarForce(0, schema.MetadataVersion, .v5);
    try b.addScalarForce(1, schema.HeaderType, .schema);
    try b.addOffset(2, sref);
    const meta = try b.finish(try b.endTable());
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try ipc.writeMessage(gpa, &out, meta, &.{});
    try ipc.writeEos(gpa, &out);
    return out.toOwnedSlice(gpa);
}

const struct_id = 13; // Schema.fbs Type union: Struct_
const null_id = 1; // Null

test "hostile schema: fields shared through offsets (a DAG) cannot multiply the decode work" {
    const gpa = testing.allocator;
    // Depth: per level a Struct field whose children vector holds the SAME child twice;
    // 40 levels of ~40 bytes each name 2^41 fields.
    {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        var r: ?fb.Ref = null;
        for (0..40) |_| {
            const kids = if (r) |x| try b.createOffsetVector(&.{ x, x }) else try b.createOffsetVector(&.{});
            b.startTable();
            try b.addScalarForce(2, u8, struct_id);
            try b.addOffset(5, kids);
            r = try b.endTable();
        }
        const bytes = try schemaOnly(gpa, &b, try b.createOffsetVector(&.{ r.?, r.? }));
        defer gpa.free(bytes);
        try testing.expect(bytes.len < 4096);
        const got = try streamUnderCap(bytes, .{}, 16 << 20);
        try testing.expectEqual(@as(?anyerror, error.Malformed), got.err);
        try testing.expect(got.peak < 1 << 20);
    }
    // Width: N top-level fields that are one Struct table, whose children are N offsets
    // to one leaf: N^2 fields from 8N bytes.
    {
        const n = 20_000;
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        b.startTable();
        try b.addScalarForce(2, u8, null_id);
        const leaf = try b.endTable();
        const refs = try gpa.alloc(fb.Ref, n);
        defer gpa.free(refs);
        @memset(refs, leaf);
        const kids = try b.createOffsetVector(refs);
        b.startTable();
        try b.addScalarForce(2, u8, struct_id);
        try b.addOffset(5, kids);
        const mid = try b.endTable();
        @memset(refs, mid);
        const bytes = try schemaOnly(gpa, &b, try b.createOffsetVector(refs));
        defer gpa.free(bytes);
        const got = try streamUnderCap(bytes, .{}, 64 << 20);
        try testing.expectEqual(@as(?anyerror, error.Malformed), got.err);
        try testing.expect(got.peak < 16 << 20);
    }
    // One 64 KiB name behind 4096 fields: the reader copies every name.
    {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        const long = try gpa.alloc(u8, 64 << 10);
        defer gpa.free(long);
        @memset(long, 'n');
        const name = try b.createString(long);
        b.startTable();
        try b.addOffset(0, name);
        try b.addScalarForce(2, u8, null_id);
        const leaf = try b.endTable();
        var refs: [4096]fb.Ref = undefined;
        @memset(&refs, leaf);
        const bytes = try schemaOnly(gpa, &b, try b.createOffsetVector(&refs));
        defer gpa.free(bytes);
        const got = try streamUnderCap(bytes, .{}, 64 << 20);
        try testing.expectEqual(@as(?anyerror, error.Malformed), got.err);
        try testing.expect(got.peak < 4 << 20);
    }
    // One 64 KiB metadata value (or key) behind 256 entries of the schema's
    // `custom_metadata`: a reader asked for the metadata copies every entry.
    for ([_]bool{ false, true }) |long_key| {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        const long = try gpa.alloc(u8, 64 << 10);
        defer gpa.free(long);
        @memset(long, 'v');
        const k = try b.createString(if (long_key) long else "k");
        const v = try b.createString(if (long_key) "v" else long);
        b.startTable();
        try b.addOffset(0, k);
        try b.addOffset(1, v);
        const kv = try b.endTable();
        const refs: [256]fb.Ref = @splat(kv);
        const md = try b.createOffsetVector(&refs);
        const empty = try b.createOffsetVector(&.{});
        b.startTable();
        try b.addOffset(1, empty);
        try b.addOffset(2, md);
        const sref = try b.endTable();
        b.startTable();
        try b.addScalarForce(0, schema.MetadataVersion, .v5);
        try b.addScalarForce(1, schema.HeaderType, .schema);
        try b.addOffset(2, sref);
        const meta = try b.finish(try b.endTable());
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try ipc.writeMessage(gpa, &out, meta, &.{});
        try ipc.writeEos(gpa, &out);
        var got_md: stream.Metadata = .{};
        const got = try streamUnderCap(out.items, .{ .metadata = &got_md }, 4 << 20);
        try testing.expectEqual(@as(?anyerror, error.Malformed), got.err);
        try testing.expect(got.peak < 1 << 20);
    }
    // The same in a file footer's `custom_metadata` (decoded in a budget of its own); one
    // entry of it reads.
    for ([_]usize{ 256, 1 }) |entries| {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        const long = try gpa.alloc(u8, 64 << 10);
        defer gpa.free(long);
        @memset(long, 'v');
        const k = try b.createString("k");
        const v = try b.createString(long);
        b.startTable();
        try b.addOffset(0, k);
        try b.addOffset(1, v);
        const kv = try b.endTable();
        var refs: [256]fb.Ref = @splat(kv);
        const md = try b.createOffsetVector(refs[0..entries]);
        const empty = try b.createOffsetVector(&.{});
        b.startTable();
        try b.addOffset(1, empty);
        const sref = try b.endTable();
        b.startTable();
        try b.addScalarForce(0, schema.MetadataVersion, .v5);
        try b.addOffset(1, sref);
        try b.addOffset(4, md);
        const footer = try b.finish(try b.endTable());
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try out.appendSlice(gpa, "ARROW1\x00\x00");
        try out.appendSlice(gpa, footer);
        try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(i32, @as(i32, @intCast(footer.len)))));
        try out.appendSlice(gpa, "ARROW1");
        var got_md: stream.Metadata = .{};
        const got = try fileUnderCap(out.items, .{ .metadata = &got_md }, 4 << 20);
        if (entries == 1) {
            try testing.expectEqual(@as(?anyerror, null), got.err);
            try testing.expectEqual(@as(usize, 1), got_md.footer.len); // (its bytes went with the arena)
        } else {
            try testing.expectEqual(@as(?anyerror, error.Malformed), got.err);
            try testing.expect(got.peak < 1 << 20);
        }
    }
    // An honest schema of the same shapes (no sharing) still decodes.
    {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        var refs: [64]fb.Ref = undefined;
        for (&refs) |*x| {
            const kids = try b.createOffsetVector(&.{});
            const nm = try b.createString("a_column_name");
            b.startTable();
            try b.addOffset(0, nm);
            try b.addScalarForce(2, u8, struct_id);
            try b.addOffset(5, kids);
            x.* = try b.endTable();
        }
        const bytes = try schemaOnly(gpa, &b, try b.createOffsetVector(&refs));
        defer gpa.free(bytes);
        try testing.expectEqual(@as(?anyerror, null), (try streamUnderCap(bytes, .{}, 16 << 20)).err);
    }
}

/// One `int` column of `n` zeros (zstd turns each batch's values into a few bytes).
fn zeros(a: Allocator, n: usize) !df.Frame {
    const vals = try a.alloc(i64, n);
    @memset(vals, 0);
    return .{ .columns = try a.dupe(df.Column, &.{.{ .name = "z", .type = .int }}), .data = try a.dupe(df.ColumnData, &.{.{ .int = .{ .values = vals } }}), .len = n };
}

test "hostile bodies: max_body_bytes caps the whole read, not one message" {
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    // Four batches of 16 Ki zeros: 128 KiB inflated each, 512 KiB in all, from a few hundred
    // bytes of zstd per batch.
    const f = try zeros(a, 1 << 16);
    const opts: stream.WriteOptions = .{ .rows_per_batch = 1 << 14, .compression = .zstd };
    const s = try stream.writeStream(gpa, f, opts);
    defer gpa.free(s);
    const fl = try stream.writeFile(gpa, f, opts);
    defer gpa.free(fl);
    try testing.expect(s.len < 8 << 10);
    // Every batch alone is under 300 KiB; together they are not.
    const tight: stream.ReadOptions = .{ .max_body_bytes = 300 << 10 };
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), (try streamUnderCap(s, tight, 4 << 20)).err);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), (try fileUnderCap(fl, tight, 4 << 20)).err);
    const roomy: stream.ReadOptions = .{ .max_body_bytes = 512 << 10 };
    try st.expectSameFrame(f, try stream.readStream(a, s, roomy));
    try st.expectSameFrame(f, try stream.readFile(a, fl, roomy));
}

/// Rebuilds a file's footer: the metadata version, and the record batch blocks as given
/// (24 bytes each) — the messages before the footer stay as they are.
fn refooter(gpa: Allocator, file: []const u8, version: schema.MetadataVersion, batch_blocks: ?[]const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const fend = file.len - 10;
    const flen: usize = @intCast(std.mem.readInt(i32, file[fend..][0..4], .little));
    const fstart = fend - flen;
    const footer = try fb.root(file[fstart..fend]);
    const s = try schema.decodeSchema(arena.allocator(), (try footer.table(1)).?);
    const blocksOf = struct {
        fn f(v: ?fb.Vector) ![]const u8 {
            const x = v orelse return &.{};
            if (x.len == 0) return &.{};
            return (try x.structAt(0, 24)).ptr[0 .. 24 * @as(usize, x.len)];
        }
    }.f;
    var b = fb.Builder.init(gpa);
    defer b.deinit();
    const sref = try schema.encodeSchema(&b, s);
    const dv = try b.createStructVector(try blocksOf(try footer.vector(2)), 24, 8);
    const rv = try b.createStructVector(batch_blocks orelse try blocksOf(try footer.vector(3)), 24, 8);
    b.startTable();
    try b.addScalarForce(0, schema.MetadataVersion, version);
    try b.addOffset(1, sref);
    try b.addOffset(2, dv);
    try b.addOffset(3, rv);
    const ft = try b.finish(try b.endTable());
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, file[0..fstart]);
    try out.appendSlice(gpa, ft);
    var len: [4]u8 = undefined;
    std.mem.writeInt(i32, &len, @intCast(ft.len), .little);
    try out.appendSlice(gpa, &len);
    try out.appendSlice(gpa, "ARROW1");
    return out.toOwnedSlice(gpa);
}

fn batchBlocks(file: []const u8) ![]const u8 {
    const fend = file.len - 10;
    const flen: usize = @intCast(std.mem.readInt(i32, file[fend..][0..4], .little));
    const footer = try fb.root(file[fend - flen .. fend]);
    const v = (try footer.vector(3)).?;
    return (try v.structAt(0, 24)).ptr[0 .. 24 * @as(usize, v.len)];
}

test "hostile footer: blocks naming one message twice, lying about its lengths, an old version" {
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try zeros(a, 1 << 12);
    const good = try stream.writeFile(gpa, f, .{ .rows_per_batch = 1 << 10, .compression = .zstd });
    defer gpa.free(good);
    // Rebuilt unchanged, the file reads.
    const same = try refooter(gpa, good, .v5, null);
    defer gpa.free(same);
    try st.expectSameFrame(f, try stream.readFile(a, same, .{}));

    const blocks = try a.dupe(u8, try batchBlocks(good));
    try testing.expectEqual(@as(usize, 4 * 24), blocks.len);
    const Case = struct { want: anyerror, version: schema.MetadataVersion = .v5, blocks: ?[]const u8 = null };
    // 1000 blocks all naming the first batch: inflated and decoded 1000 times before.
    const many = try a.alloc(u8, 1000 * 24);
    for (0..1000) |i| @memcpy(many[i * 24 ..][0..24], blocks[0..24]);
    // The block's metadata length off by 8; its body length off by 64.
    const meta_off = try a.dupe(u8, blocks);
    std.mem.writeInt(i32, meta_off[8..12], std.mem.readInt(i32, meta_off[8..12], .little) + 8, .little);
    const body_off = try a.dupe(u8, blocks);
    std.mem.writeInt(i64, body_off[16..24], std.mem.readInt(i64, body_off[16..24], .little) + 64, .little);
    const cases = [_]Case{
        .{ .want = error.Malformed, .blocks = many },
        .{ .want = error.Malformed, .blocks = meta_off },
        .{ .want = error.Malformed, .blocks = body_off },
        .{ .want = error.Unsupported, .version = .v3 },
        .{ .want = error.Unsupported, .version = @fromBackingInt(@intCast(9)) },
    };
    for (cases, 0..) |c, i| {
        const bad = try refooter(gpa, good, c.version, c.blocks);
        defer gpa.free(bad);
        const got = try fileUnderCap(bad, .{}, 16 << 20);
        if (got.err == null or got.err.? != c.want) {
            std.debug.print("footer case {d}: want {s}\n", .{ i, @errorName(c.want) });
            return error.TestUnexpectedResult;
        }
    }
    // Blocks reordered (not shared) are fine: the batches read in footer order.
    const swapped = try a.dupe(u8, blocks);
    @memcpy(swapped[0..24], blocks[24..48]);
    @memcpy(swapped[24..48], blocks[0..24]);
    const sw = try refooter(gpa, good, .v4, swapped);
    defer gpa.free(sw);
    try st.expectSameFrame(f, try stream.readFile(a, sw, .{}));
}

test "hostile batches: many columns whose rows cost no body bytes stop at max_cells" {
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    // 64 FixedSizeBinary(0) columns of 4096 rows each: no body at all, 8 bytes of offsets
    // per row and column on read.
    const cols = 64;
    const rows = 4096;
    var fields: [cols]schema.Field = undefined;
    for (&fields) |*x| x.* = .{ .name = "z", .type = .{ .fixed_size_binary = 0 } };
    var nodes: [cols]ipc.FieldNode = undefined;
    @memset(&nodes, .{ .length = rows, .null_count = 0 });
    var bufs: [2 * cols][]const u8 = undefined;
    @memset(&bufs, "");
    const bytes = try st.hand(gpa, &fields, &.{.{ .length = rows, .nodes = &nodes, .bufs = &bufs }});
    defer gpa.free(bytes);
    const got = try streamUnderCap(bytes, .{ .max_cells = cols * rows - 1 }, 64 << 20);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), got.err);
    try testing.expect(got.peak < 1 << 20);
    // At the budget it reads: every cell an empty binary.
    const f = try stream.readStream(a, bytes, .{ .max_cells = cols * rows });
    try testing.expectEqual(@as(usize, rows), f.len);
    try testing.expectEqualStrings("", f.columnAt(cols - 1).get(rows - 1).text);

    // One FixedSizeList(0) column the same way.
    const item = [_]schema.Field{.{ .name = "item", .type = .null }};
    const fsl = [_]schema.Field{.{ .name = "l", .type = .{ .fixed_size_list = 0 }, .children = &item }};
    const lb = try st.hand(gpa, &fsl, &.{.{ .length = 1 << 20, .nodes = &.{ .{ .length = 1 << 20, .null_count = 0 }, .{ .length = 0, .null_count = 0 } }, .bufs = &.{""} }});
    defer gpa.free(lb);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), (try streamUnderCap(lb, .{ .max_cells = 1 << 19 }, 1 << 20)).err);
}

test "hostile dictionaries: an entry copied into many rows counts against max_cells" {
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    // A Binary dictionary of one 4 KiB entry; 4096 one-byte indices to it: 16 MiB of copies
    // from 8 KiB of body.
    const fields = [_]schema.Field{.{ .name = "b", .type = .binary, .dictionary = .{ .id = 0, .index = .{ .bits = 8, .signed = true } } }};
    const entry = try a.alloc(u8, 4096);
    @memset(entry, 'e');
    const idx = try a.alloc(u8, 4096);
    @memset(idx, 0);
    const bytes = try st.hand(gpa, &fields, &.{
        .{ .length = 1, .dict_id = 0, .nodes = &.{.{ .length = 1, .null_count = 0 }}, .bufs = &.{ "", st.bytesOf(i32, &.{ 0, 4096 }), entry } },
        .{ .length = 4096, .nodes = &.{.{ .length = 4096, .null_count = 0 }}, .bufs = &.{ "", idx } },
    });
    defer gpa.free(bytes);
    const got = try streamUnderCap(bytes, .{ .max_cells = 1 << 20 }, 8 << 20);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), got.err);
    const f = try stream.readStream(a, bytes, .{});
    try testing.expectEqual(@as(usize, 4096), f.columnAt(0).get(4095).text.len);

    // A List dictionary entry of 2^20 Null elements, 64 rows to it: 2^26 selectors from a
    // body of a few bytes.
    const item = [_]schema.Field{.{ .name = "item", .type = .null }};
    const lf = [_]schema.Field{.{ .name = "l", .type = .list, .children = &item, .dictionary = .{ .id = 0, .index = .{ .bits = 8, .signed = true } } }};
    var idx64: [64]u8 = @splat(0);
    const lb = try st.hand(gpa, &lf, &.{
        .{ .length = 1, .dict_id = 0, .nodes = &.{ .{ .length = 1, .null_count = 0 }, .{ .length = 1 << 20, .null_count = 1 << 20 } }, .bufs = &.{ "", st.bytesOf(i32, &.{ 0, 1 << 20 }) } },
        .{ .length = 64, .nodes = &.{.{ .length = 64, .null_count = 0 }}, .bufs = &.{ "", &idx64 } },
    });
    defer gpa.free(lb);
    // The dictionary itself is 2^20 + 1 slots; the first row copied out of it passes 2^21.
    const lg = try streamUnderCap(lb, .{ .max_cells = 1 << 21 }, 64 << 20);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), lg.err);
    try testing.expect(lg.peak < 32 << 20);
}

test "hostile decimals: a Decimal256 / Decimal32 node longer than its buffer allocates nothing for it" {
    const gpa = testing.allocator;
    for ([_]i32{ 32, 64, 256 }) |bits| {
        const fields = [_]schema.Field{.{ .name = "d", .type = .{ .decimal = .{ .precision = 9, .scale = 0, .bits = bits } } }};
        const rows = 1 << 24;
        const z: [32]u8 = @splat(0);
        const bytes = try st.hand(gpa, &fields, &.{.{ .length = rows, .nodes = &.{.{ .length = rows, .null_count = 0 }}, .bufs = &.{ "", &z } }});
        defer gpa.free(bytes);
        const got = try streamUnderCap(bytes, .{ .max_rows = 1 << 25, .max_cells = 1 << 25 }, 4 << 20);
        try testing.expectEqual(@as(?anyerror, error.Malformed), got.err);
        try testing.expect(got.peak < 1 << 20);
    }
}

test "hostile run-end encoding: one run of 2^22 rows from a few bytes stops at max_cells before it is expanded" {
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const kids = [_]schema.Field{
        .{ .name = "run_ends", .nullable = false, .type = .{ .int = .{ .bits = 32, .signed = true } } },
        .{ .name = "values", .type = .utf8 },
    };
    const fields = [_]schema.Field{.{ .name = "r", .type = .run_end_encoded, .children = &kids }};
    const make = struct {
        fn f(g: Allocator, rows: i32, value: []const u8) ![]u8 {
            var ends: [4]u8 = undefined;
            std.mem.writeInt(i32, &ends, rows, .little);
            var offs: [8]u8 = undefined;
            std.mem.writeInt(i32, offs[0..4], 0, .little);
            std.mem.writeInt(i32, offs[4..8], @intCast(value.len), .little);
            return st.hand(g, &fields, &.{.{ .length = rows, .nodes = &.{ .{ .length = rows, .null_count = 0 }, .{ .length = 1, .null_count = 0 }, .{ .length = 1, .null_count = 0 } }, .bufs = &.{ "", &ends, "", &offs, value } }});
        }
    }.f;
    // One 64-byte value behind 2^22 rows: 2^22 selectors and 2^28 bytes of copies.
    const value: [64]u8 = @splat('v');
    const big = try make(gpa, 1 << 22, &value);
    defer gpa.free(big);
    const got = try streamUnderCap(big, .{ .max_cells = (1 << 22) + 100 }, 8 << 20);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), got.err);
    try testing.expect(got.peak < 1 << 20);
    // The copies are charged per byte too: 2^20 rows fit 2^22 slots, their 2^26 bytes do not.
    const mid = try make(gpa, 1 << 20, &value);
    defer gpa.free(mid);
    const got2 = try streamUnderCap(mid, .{ .max_cells = 1 << 22 }, 48 << 20);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), got2.err);
    // A run of 4096 rows reads.
    const small = try make(gpa, 4096, &value);
    defer gpa.free(small);
    const f = try stream.readStream(a, small, .{});
    try testing.expectEqual(@as(usize, 4096), f.len);
    try testing.expectEqualStrings(&value, f.columnAt(0).get(4095).text);
}

test "hostile views: many views of one long slice, list views of one whole child (a Null one too), stop at max_cells" {
    const gpa = testing.allocator;
    // 2^16 Utf8View rows, each naming the same 64 KiB of one data buffer: 4 GiB of copies
    // from 1 MiB of views.
    {
        const rows = 1 << 16;
        const data = try gpa.alloc(u8, 64 << 10);
        defer gpa.free(data);
        @memset(data, 'd');
        const v = st.view(data, 0, 0);
        const views = try gpa.alloc(u8, rows * 16);
        defer gpa.free(views);
        for (0..rows) |i| @memcpy(views[i * 16 ..][0..16], &v);
        const fields = [_]schema.Field{.{ .name = "s", .type = .utf8_view }};
        const bytes = try st.hand(gpa, &fields, &.{.{ .length = rows, .variadic = &.{1}, .nodes = &.{.{ .length = rows, .null_count = 0 }}, .bufs = &.{ "", views, data } }});
        defer gpa.free(bytes);
        const got = try streamUnderCap(bytes, .{}, 16 << 20);
        try testing.expectEqual(@as(?anyerror, error.LimitExceeded), got.err);
        try testing.expect(got.peak < 4 << 20);
    }
    // 2^14 ListView rows, each the whole child of 2^14 elements: 2^28 selectors.
    {
        const rows = 1 << 14;
        const offs = try gpa.alloc(i32, rows);
        defer gpa.free(offs);
        @memset(offs, 0);
        const sizes = try gpa.alloc(i32, rows);
        defer gpa.free(sizes);
        @memset(sizes, rows);
        const child = try gpa.alloc(i32, rows);
        defer gpa.free(child);
        @memset(child, 7);
        const item = [_]schema.Field{.{ .name = "item", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
        const fields = [_]schema.Field{.{ .name = "l", .type = .list_view, .children = &item }};
        const node: ipc.FieldNode = .{ .length = rows, .null_count = 0 };
        const bytes = try st.hand(gpa, &fields, &.{.{ .length = rows, .nodes = &.{ node, node }, .bufs = &.{ "", std.mem.sliceAsBytes(offs), std.mem.sliceAsBytes(sizes), "", std.mem.sliceAsBytes(child) } }});
        defer gpa.free(bytes);
        const got = try streamUnderCap(bytes, .{ .max_cells = 1 << 24 }, 16 << 20);
        try testing.expectEqual(@as(?anyerror, error.LimitExceeded), got.err);
        try testing.expect(got.peak < 4 << 20);
    }
    // 65535 ListView rows, each the whole Null child of 65535: no copy to make, but the
    // frame would hold 65535^2 (just under 2^32) elements for a writer or a walker.
    {
        const rows = 65535;
        const offs = try gpa.alloc(i32, rows);
        defer gpa.free(offs);
        @memset(offs, 0);
        const sizes = try gpa.alloc(i32, rows);
        defer gpa.free(sizes);
        @memset(sizes, rows);
        const item = [_]schema.Field{.{ .name = "item", .type = .null }};
        const fields = [_]schema.Field{.{ .name = "l", .type = .list_view, .children = &item }};
        const bytes = try st.hand(gpa, &fields, &.{.{ .length = rows, .nodes = &.{ .{ .length = rows, .null_count = 0 }, .{ .length = rows, .null_count = rows } }, .bufs = &.{ "", std.mem.sliceAsBytes(offs), std.mem.sliceAsBytes(sizes) } }});
        defer gpa.free(bytes);
        const got = try streamUnderCap(bytes, .{ .max_cells = 1 << 20 }, 16 << 20);
        try testing.expectEqual(@as(?anyerror, error.LimitExceeded), got.err);
        try testing.expect(got.peak < 4 << 20);
    }
    // 65536 such rows of a 65536-slot child: 2^32 elements, past `dataframe`'s u32 list
    // offsets, refused as the sizes are summed (before any charge).
    {
        const rows = 65536;
        const offs = try gpa.alloc(i32, rows);
        defer gpa.free(offs);
        @memset(offs, 0);
        const sizes = try gpa.alloc(i32, rows);
        defer gpa.free(sizes);
        @memset(sizes, rows);
        const item = [_]schema.Field{.{ .name = "item", .type = .null }};
        const fields = [_]schema.Field{.{ .name = "l", .type = .list_view, .children = &item }};
        const bytes = try st.hand(gpa, &fields, &.{.{ .length = rows, .nodes = &.{ .{ .length = rows, .null_count = 0 }, .{ .length = rows, .null_count = rows } }, .bufs = &.{ "", std.mem.sliceAsBytes(offs), std.mem.sliceAsBytes(sizes) } }});
        defer gpa.free(bytes);
        const got = try streamUnderCap(bytes, .{ .max_cells = 1 << 40 }, 16 << 20);
        try testing.expectEqual(@as(?anyerror, error.Unsupported), got.err);
    }
}

test "hostile map: 2^22 entries of zero-width keys and Null values from a few bytes stop at max_cells" {
    const gpa = testing.allocator;
    const n = 1 << 22;
    const kv = [_]schema.Field{
        .{ .name = "key", .nullable = false, .type = .{ .fixed_size_binary = 0 } },
        .{ .name = "value", .type = .null },
    };
    const entries = [_]schema.Field{.{ .name = "entries", .nullable = false, .type = .@"struct", .children = &kv }};
    const fields = [_]schema.Field{.{ .name = "m", .type = .{ .map = false }, .children = &entries }};
    var offs: [8]u8 = undefined;
    std.mem.writeInt(i32, offs[0..4], 0, .little);
    std.mem.writeInt(i32, offs[4..8], n, .little);
    const e: ipc.FieldNode = .{ .length = n, .null_count = 0 };
    const bytes = try st.hand(gpa, &fields, &.{.{ .length = 1, .nodes = &.{ .{ .length = 1, .null_count = 0 }, e, e, .{ .length = n, .null_count = n } }, .bufs = &.{ "", &offs, "", "", "" } }});
    defer gpa.free(bytes);
    const got = try streamUnderCap(bytes, .{ .max_cells = 1 << 20 }, 4 << 20);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), got.err);
    try testing.expect(got.peak < 1 << 20);
    // A child shorter than the offsets claim is Malformed, not read past.
    const short: ipc.FieldNode = .{ .length = n - 1, .null_count = 0 };
    const cut = try st.hand(gpa, &fields, &.{.{ .length = 1, .nodes = &.{ .{ .length = 1, .null_count = 0 }, short, short, .{ .length = n - 1, .null_count = n - 1 } }, .bufs = &.{ "", &offs, "", "", "" } }});
    defer gpa.free(cut);
    const got2 = try streamUnderCap(cut, .{}, 4 << 20);
    try testing.expectEqual(@as(?anyerror, error.Malformed), got2.err);
}

test "hostile dictionaries: a dictionary replaced many times is charged every time (max_cells, max_rows, max_body_bytes)" {
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    // 1024 replacements of a FixedSizeBinary(0) dictionary of 2^16 entries: no body bytes,
    // 2^26 entries kept (every generation stays readable) from ~200 KB of metadata.
    const n = 1 << 16;
    const reps = 1024;
    const fields = [_]schema.Field{
        .{ .name = "z", .type = .{ .fixed_size_binary = 0 }, .dictionary = .{ .id = 0, .index = .{ .bits = 8, .signed = true } } },
        .{ .name = "x", .type = .{ .int = .{ .bits = 8, .signed = true } } },
    };
    const batches = try a.alloc(st.HandBatch, reps + 1);
    for (batches[0..reps]) |*b| b.* = .{ .length = n, .dict_id = 0, .nodes = &.{.{ .length = n, .null_count = 0 }}, .bufs = &.{ "", "" } };
    batches[reps] = .{ .length = 1, .nodes = &.{ .{ .length = 1, .null_count = 0 }, .{ .length = 1, .null_count = 0 } }, .bufs = &.{ "", &.{0}, "", &.{5} } };
    const bytes = try st.hand(gpa, &fields, batches);
    defer gpa.free(bytes);
    // Each replacement alone fits; together they pass max_cells before anything is decoded.
    const got = try streamUnderCap(bytes, .{ .max_cells = 1 << 24 }, 16 << 20);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), got.err);
    try testing.expect(got.peak < 4 << 20);
    // The generations are one array of 2^26 entries against max_rows.
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), (try streamUnderCap(bytes, .{ .max_rows = 1 << 22 }, 16 << 20)).err);
    // Not projected, the dictionary is neither charged nor decoded.
    const xs = [_]stream.ColumnRef{.{ .name = "x" }};
    const px = try streamUnderCap(bytes, .{ .max_cells = 1 << 24, .max_rows = 1 << 22, .columns = &xs }, 16 << 20);
    try testing.expectEqual(@as(?anyerror, null), px.err);
    // Four generations read.
    const few = try st.hand(gpa, &fields, batches[reps - 4 ..]);
    defer gpa.free(few);
    const f = try stream.readStream(a, few, .{ .max_cells = 1 << 24 });
    try testing.expectEqualStrings("", f.columnAt(0).get(0).text);

    // A zstd-compressed dictionary of one 64 KiB text sent 64 times: a few hundred bytes
    // each, 4 MiB inflated in all, against the read-wide max_body_bytes.
    const big = try a.alloc(u8, 64 << 10);
    @memset(big, 'a');
    const cf: df.Frame = .{
        .columns = &.{.{ .name = "c", .type = .categorical }},
        .data = try a.dupe(df.ColumnData, &.{.{ .categorical = .{ .codes = .{ .values = &.{0} }, .dict = try st.textCol(a, &.{big}) } }}),
        .len = 1,
    };
    const once = try stream.writeStream(gpa, cf, .{ .compression = .zstd });
    defer gpa.free(once);
    var pos: usize = 0;
    _ = try ipc.readMessage(once, &pos);
    const dict_at = pos;
    const dm = try ipc.readMessage(once, &pos);
    try testing.expectEqual(schema.HeaderType.dictionary_batch, dm.msg.header_type);
    const batch_at = pos;
    try testing.expect(batch_at - dict_at < 1 << 10);
    var many: std.ArrayList(u8) = .empty;
    defer many.deinit(gpa);
    try many.appendSlice(gpa, once[0..dict_at]);
    for (0..64) |_| try many.appendSlice(gpa, once[dict_at..batch_at]);
    try many.appendSlice(gpa, once[batch_at..]);
    try testing.expectEqual(@as(?anyerror, error.LimitExceeded), (try streamUnderCap(many.items, .{ .max_body_bytes = 1 << 20 }, 16 << 20)).err);
    try st.expectSameFrame(cf, try stream.readStream(a, many.items, .{ .max_body_bytes = 8 << 20 }));
}
