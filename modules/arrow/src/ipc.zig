// SPDX-License-Identifier: MIT

//! The Arrow IPC framing: encapsulated messages (continuation marker,
//! metadata length, a FlatBuffers `Message`, padding to 8 bytes, the body),
//! the end-of-stream marker, and the `RecordBatch` / `DictionaryBatch`
//! metadata tables (`Message.fbs`): field nodes, buffer locations, body
//! compression. The column data itself is laid out by the frame layer.

const std = @import("std");
const fb = @import("fb.zig");
const schema = @import("schema.zig");

pub const Error = schema.Error || error{EndOfStream};

pub const continuation: u32 = 0xFFFF_FFFF;

/// One message as found in a stream or file: its metadata bytes (the `Message`
/// FlatBuffer, padding included) and its body.
pub const Encapsulated = struct {
    metadata: []const u8,
    body: []const u8,
};

/// One message read by `readMessage`: its bytes and its decoded envelope.
pub const Read = struct { enc: Encapsulated, msg: schema.Message };

/// Reads the encapsulated message starting at `buf[pos.*]` and advances `pos`.
/// `error.EndOfStream` at the end-of-stream marker (or at the end of `buf`, or
/// at a pre-0.15 zero length). Accepts the legacy framing without the
/// continuation marker. Every length is checked against `buf`.
pub fn readMessage(buf: []const u8, pos: *usize) Error!Read {
    var p = pos.*;
    if (p == buf.len) return error.EndOfStream;
    if (buf.len - p < 4) return error.Malformed;
    var len = std.mem.readInt(u32, buf[p..][0..4], .little);
    p += 4;
    if (len == continuation) {
        if (buf.len - p < 4) return error.Malformed;
        len = std.mem.readInt(u32, buf[p..][0..4], .little);
        p += 4;
    }
    if (len == 0) return error.EndOfStream;
    if (len > buf.len - p) return error.Malformed;
    const meta = buf[p..][0..len];
    p += len;
    const msg = try schema.decodeMessage(meta);
    const body_len: u64 = @intCast(msg.body_length);
    if (body_len > buf.len - p) return error.Malformed;
    const body = buf[p..][0..@intCast(body_len)];
    p += @intCast(body_len);
    pos.* = p;
    return .{ .enc = .{ .metadata = meta, .body = body }, .msg = msg };
}

/// Appends one encapsulated message: marker, padded metadata length, the
/// metadata padded to 8 bytes, then `body` (whose length must already be a
/// multiple of 8, as `BodyBuilder` makes it).
pub fn writeMessage(gpa: std.mem.Allocator, out: *std.ArrayList(u8), metadata: []const u8, body: []const u8) error{OutOfMemory}!void {
    std.debug.assert(body.len % 8 == 0);
    const padded = std.mem.alignForward(usize, metadata.len, 8);
    // The 8-byte prefix keeps the metadata (and so the body after it) 8-aligned in the output.
    try out.ensureUnusedCapacity(gpa, 8 + padded + body.len);
    out.appendSliceAssumeCapacity(&std.mem.toBytes(std.mem.nativeToLittle(u32, continuation)));
    out.appendSliceAssumeCapacity(&std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, @intCast(padded)))));
    out.appendSliceAssumeCapacity(metadata);
    out.appendNTimesAssumeCapacity(0, padded - metadata.len);
    out.appendSliceAssumeCapacity(body);
}

/// The end-of-stream marker.
pub fn writeEos(gpa: std.mem.Allocator, out: *std.ArrayList(u8)) error{OutOfMemory}!void {
    try out.appendSlice(gpa, &.{ 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 });
}

// ── RecordBatch metadata ────────────────────────────────────────────────────

pub const FieldNode = struct { length: i64, null_count: i64 };
pub const BufferLoc = struct { offset: i64, length: i64 };
pub const Codec = enum(i8) { lz4_frame = 0, zstd = 1, _ };

pub const RecordBatch = struct {
    length: i64,
    nodes: []const FieldNode,
    buffers: []const BufferLoc,
    compression: ?Codec = null,
};

/// Decodes a `RecordBatch` table (slices from `arena`). Every node and buffer
/// is checked: lengths and counts non-negative, null counts not above lengths,
/// buffers inside `body_len`.
pub fn decodeRecordBatch(arena: std.mem.Allocator, t: fb.Table, body_len: u64) Error!RecordBatch {
    const length = try t.scalar(i64, 0, 0);
    if (length < 0) return error.Malformed;
    var nodes: []FieldNode = &.{};
    if (try t.vector(1)) |v| {
        nodes = try arena.alloc(FieldNode, v.len);
        for (nodes, 0..) |*n, i| {
            const raw = try v.structAt(i, 16);
            n.* = .{ .length = std.mem.readInt(i64, raw[0..8], .little), .null_count = std.mem.readInt(i64, raw[8..16], .little) };
            if (n.length < 0 or n.null_count < 0 or n.null_count > n.length) return error.Malformed;
        }
    }
    var bufs: []BufferLoc = &.{};
    if (try t.vector(2)) |v| {
        bufs = try arena.alloc(BufferLoc, v.len);
        for (bufs, 0..) |*b, i| {
            const raw = try v.structAt(i, 16);
            b.* = .{ .offset = std.mem.readInt(i64, raw[0..8], .little), .length = std.mem.readInt(i64, raw[8..16], .little) };
            if (b.offset < 0 or b.length < 0) return error.Malformed;
            const end = @as(u64, @intCast(b.offset)) +| @as(u64, @intCast(b.length));
            if (end > body_len) return error.Malformed;
        }
    }
    var codec: ?Codec = null;
    if (try t.table(3)) |c| {
        const method = try c.scalar(i8, 1, 0);
        if (method != 0) return error.Unsupported; // BUFFER is the only method
        codec = try c.scalar(Codec, 0, .lz4_frame);
    }
    return .{ .length = length, .nodes = nodes, .buffers = bufs, .compression = codec };
}

/// Builds a `RecordBatch` table.
pub fn encodeRecordBatch(b: *fb.Builder, rb: RecordBatch) error{OutOfMemory}!fb.Ref {
    const nodes_bytes = try b.gpa.alloc(u8, rb.nodes.len * 16);
    defer b.gpa.free(nodes_bytes);
    for (rb.nodes, 0..) |n, i| {
        std.mem.writeInt(i64, nodes_bytes[i * 16 ..][0..8], n.length, .little);
        std.mem.writeInt(i64, nodes_bytes[i * 16 + 8 ..][0..8], n.null_count, .little);
    }
    const nodes = try b.createStructVector(nodes_bytes, 16, 8);
    const buf_bytes = try b.gpa.alloc(u8, rb.buffers.len * 16);
    defer b.gpa.free(buf_bytes);
    for (rb.buffers, 0..) |x, i| {
        std.mem.writeInt(i64, buf_bytes[i * 16 ..][0..8], x.offset, .little);
        std.mem.writeInt(i64, buf_bytes[i * 16 + 8 ..][0..8], x.length, .little);
    }
    const bufs = try b.createStructVector(buf_bytes, 16, 8);
    var comp: ?fb.Ref = null;
    if (rb.compression) |c| {
        b.startTable();
        try b.addScalarForce(0, Codec, c);
        comp = try b.endTable();
    }
    b.startTable();
    try b.addScalar(0, i64, rb.length, 0);
    try b.addOffset(1, nodes);
    try b.addOffset(2, bufs);
    if (comp) |c| try b.addOffset(3, c);
    return b.endTable();
}

/// A finished `Message` holding a record batch (owned by `b`).
pub fn encodeRecordBatchMessage(b: *fb.Builder, rb: RecordBatch, body_len: i64) error{OutOfMemory}![]const u8 {
    const r = try encodeRecordBatch(b, rb);
    return finishMessage(b, .record_batch, r, body_len);
}

pub const DictionaryBatch = struct { id: i64, data: RecordBatch, is_delta: bool };

pub fn decodeDictionaryBatch(arena: std.mem.Allocator, t: fb.Table, body_len: u64) Error!DictionaryBatch {
    return .{
        .id = try t.scalar(i64, 0, 0),
        .data = try decodeRecordBatch(arena, try t.table(1) orelse return error.Malformed, body_len),
        .is_delta = try t.scalar(bool, 2, false),
    };
}

pub fn encodeDictionaryBatchMessage(b: *fb.Builder, db: DictionaryBatch, body_len: i64) error{OutOfMemory}![]const u8 {
    const data = try encodeRecordBatch(b, db.data);
    b.startTable();
    try b.addScalar(0, i64, db.id, 0);
    try b.addOffset(1, data);
    try b.addScalar(2, bool, db.is_delta, false);
    const r = try b.endTable();
    return finishMessage(b, .dictionary_batch, r, body_len);
}

fn finishMessage(b: *fb.Builder, ht: schema.HeaderType, header: fb.Ref, body_len: i64) error{OutOfMemory}![]const u8 {
    b.startTable();
    try b.addScalarForce(0, schema.MetadataVersion, .v5);
    try b.addScalarForce(1, schema.HeaderType, ht);
    try b.addOffset(2, header);
    try b.addScalar(3, i64, body_len, 0);
    return b.finish(try b.endTable());
}

// ── body ────────────────────────────────────────────────────────────────────

/// Collects a message body: each buffer padded to 64 bytes (the alignment
/// Arrow recommends, so a reader may map buffers for SIMD), its location
/// recorded for the `RecordBatch` table.
pub const BodyBuilder = struct {
    bytes: std.ArrayList(u8) = .empty,
    locs: std.ArrayList(BufferLoc) = .empty,

    pub fn deinit(bb: *BodyBuilder, gpa: std.mem.Allocator) void {
        bb.bytes.deinit(gpa);
        bb.locs.deinit(gpa);
    }

    pub fn add(bb: *BodyBuilder, gpa: std.mem.Allocator, data: []const u8) error{OutOfMemory}!void {
        const off = bb.bytes.items.len;
        try bb.bytes.appendSlice(gpa, data);
        const padded = std.mem.alignForward(usize, bb.bytes.items.len, 64);
        try bb.bytes.appendNTimes(gpa, 0, padded - bb.bytes.items.len);
        try bb.locs.append(gpa, .{ .offset = @intCast(off), .length = @intCast(data.len) });
    }

    /// An absent buffer (a validity bitmap of a column without nulls).
    pub fn addEmpty(bb: *BodyBuilder, gpa: std.mem.Allocator) error{OutOfMemory}!void {
        try bb.locs.append(gpa, .{ .offset = @intCast(bb.bytes.items.len), .length = 0 });
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "stream framing: schema and record batch messages round trip, EOS ends the stream" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    var b1 = fb.Builder.init(gpa);
    defer b1.deinit();
    const fields = [_]schema.Field{.{ .name = "x", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
    try writeMessage(gpa, &out, try schema.encodeSchemaMessage(&b1, .{ .fields = &fields }), &.{});

    var body: BodyBuilder = .{};
    defer body.deinit(gpa);
    try body.addEmpty(gpa); // validity: no nulls
    try body.add(gpa, std.mem.sliceAsBytes(&[_]i32{ 1, 2, 3 }));
    var b2 = fb.Builder.init(gpa);
    defer b2.deinit();
    const rb: RecordBatch = .{ .length = 3, .nodes = &.{.{ .length = 3, .null_count = 0 }}, .buffers = body.locs.items };
    try writeMessage(gpa, &out, try encodeRecordBatchMessage(&b2, rb, @intCast(body.bytes.items.len)), body.bytes.items);
    try writeEos(gpa, &out);
    try testing.expectEqual(@as(usize, 0), out.items.len % 8);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pos: usize = 0;
    const m1 = try readMessage(out.items, &pos);
    try testing.expectEqual(schema.HeaderType.schema, m1.msg.header_type);
    const s = try schema.decodeSchema(arena, m1.msg.header.?);
    try testing.expectEqualStrings("x", s.fields[0].name);
    const m2 = try readMessage(out.items, &pos);
    try testing.expectEqual(schema.HeaderType.record_batch, m2.msg.header_type);
    const got = try decodeRecordBatch(arena, m2.msg.header.?, m2.enc.body.len);
    try testing.expectEqual(@as(i64, 3), got.length);
    try testing.expectEqual(@as(usize, 2), got.buffers.len);
    const vals = m2.enc.body[@intCast(got.buffers[1].offset)..][0..@intCast(got.buffers[1].length)];
    try testing.expectEqual(@as(i32, 2), std.mem.readInt(i32, vals[4..8], .little));
    try testing.expectError(error.EndOfStream, readMessage(out.items, &pos));
}

test "record batch metadata: negative or out-of-body values are refused" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const cases = [_]RecordBatch{
        .{ .length = -1, .nodes = &.{}, .buffers = &.{} },
        .{ .length = 1, .nodes = &.{.{ .length = 1, .null_count = 2 }}, .buffers = &.{} },
        .{ .length = 1, .nodes = &.{}, .buffers = &.{.{ .offset = 8, .length = 64 }} },
        .{ .length = 1, .nodes = &.{}, .buffers = &.{.{ .offset = -8, .length = 8 }} },
        .{ .length = 1, .nodes = &.{}, .buffers = &.{.{ .offset = std.math.maxInt(i64), .length = std.math.maxInt(i64) }} },
    };
    for (cases) |c| {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        const buf = try encodeRecordBatchMessage(&b, c, 64);
        const m = try schema.decodeMessage(buf);
        try testing.expectError(error.Malformed, decodeRecordBatch(arena_state.allocator(), m.header.?, 64));
    }
}

test "framing: every truncation of a stream is an error or a clean end, never a crash" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var b1 = fb.Builder.init(gpa);
    defer b1.deinit();
    const fields = [_]schema.Field{.{ .name = "s", .type = .utf8 }};
    try writeMessage(gpa, &out, try schema.encodeSchemaMessage(&b1, .{ .fields = &fields }), &.{});
    try writeEos(gpa, &out);
    for (0..out.items.len) |n| {
        var pos: usize = 0;
        while (true) {
            _ = readMessage(out.items[0..n], &pos) catch break;
        }
    }
}

test "framing: a stream may end without the marker, its last metadata or body flush with the end" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var b1 = fb.Builder.init(gpa);
    defer b1.deinit();
    const fields = [_]schema.Field{.{ .name = "x", .type = .{ .int = .{ .bits = 32, .signed = true } } }};
    try writeMessage(gpa, &out, try schema.encodeSchemaMessage(&b1, .{ .fields = &fields }), &.{});
    var pos: usize = 0;
    _ = try readMessage(out.items, &pos); // metadata ending exactly at the end
    try testing.expectError(error.EndOfStream, readMessage(out.items, &pos));

    var body: BodyBuilder = .{};
    defer body.deinit(gpa);
    try body.add(gpa, std.mem.sliceAsBytes(&[_]i32{ 1, 2 }));
    var b2 = fb.Builder.init(gpa);
    defer b2.deinit();
    const rb: RecordBatch = .{ .length = 2, .nodes = &.{.{ .length = 2, .null_count = 0 }}, .buffers = body.locs.items };
    try writeMessage(gpa, &out, try encodeRecordBatchMessage(&b2, rb, @intCast(body.bytes.items.len)), body.bytes.items);
    pos = 0;
    _ = try readMessage(out.items, &pos);
    const m = try readMessage(out.items, &pos); // body ending exactly at the end
    try testing.expectEqual(@as(usize, 64), m.enc.body.len);
    try testing.expectEqual(out.items.len, pos);
    try testing.expectError(error.EndOfStream, readMessage(out.items, &pos));
}

test "framing: metadata is padded to 8 bytes and its length prefix counts the padding" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try writeMessage(gpa, &out, "12345", &.{});
    try testing.expectEqual(@as(usize, 16), out.items.len);
    try testing.expectEqual(@as(u32, 8), std.mem.readInt(u32, out.items[4..8], .little));
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, out.items[13..16]);
}

test "body: every buffer starts on a 64-byte boundary" {
    var body: BodyBuilder = .{};
    defer body.deinit(testing.allocator);
    try body.add(testing.allocator, "abc");
    try body.add(testing.allocator, "defgh");
    try testing.expectEqual(@as(i64, 64), body.locs.items[1].offset);
    try testing.expectEqual(@as(usize, 128), body.bytes.items.len);
}

test "record batch metadata: a negative null count and a compression method other than BUFFER are refused" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        const buf = try encodeRecordBatchMessage(&b, .{ .length = 1, .nodes = &.{.{ .length = 1, .null_count = -1 }}, .buffers = &.{} }, 0);
        const m = try schema.decodeMessage(buf);
        try testing.expectError(error.Malformed, decodeRecordBatch(arena_state.allocator(), m.header.?, 0));
    }
    var b = fb.Builder.init(gpa);
    defer b.deinit();
    b.startTable();
    try b.addScalarForce(0, Codec, .zstd);
    try b.addScalarForce(1, i8, 1); // method: not BUFFER
    const comp = try b.endTable();
    b.startTable();
    try b.addOffset(3, comp);
    const buf = try b.finish(try b.endTable());
    try testing.expectError(error.Unsupported, decodeRecordBatch(arena_state.allocator(), try fb.root(buf), 0));
}
