// SPDX-License-Identifier: MIT

//! The FlatBuffers subset Arrow's metadata uses (`Schema.fbs`, `Message.fbs`,
//! `File.fbs`): tables with vtables, scalars with defaults, offsets to tables,
//! strings and vectors, inline structs, unions as a type byte plus a table.
//! Written from the FlatBuffers binary format description (flatbuffers.dev,
//! "FlatBuffers internals"); no FlatBuffers source was read or ported.
//!
//! Reading is defensive: every offset, vtable, vector length and string is
//! checked against the buffer, so a hostile message is `error.Malformed`,
//! never an out-of-bounds read or a panic. Building is back to front, as the
//! format is meant to be built: a child (string, vector, table) is written
//! before the table that refers to it, so every unsigned offset points
//! forward.

const std = @import("std");

pub const Error = error{Malformed};

fn readInt(comptime T: type, buf: []const u8, pos: usize) Error!T {
    const n = @sizeOf(T);
    if (pos > buf.len or buf.len - pos < n) return error.Malformed;
    return std.mem.readInt(T, buf[pos..][0..n], .little);
}

fn readScalar(comptime T: type, buf: []const u8, pos: usize) Error!T {
    return switch (@typeInfo(T)) {
        .int => readInt(T, buf, pos),
        .bool => (try readInt(u8, buf, pos)) != 0,
        .float => |f| @bitCast(try readInt(std.meta.Int(.unsigned, f.bits), buf, pos)),
        .@"enum" => |e| std.enums.fromInt(T, try readInt(e.tag_type, buf, pos)) orelse error.Malformed,
        else => @compileError("fb: no scalar reader for " ++ @typeName(T)),
    };
}

/// The target of the unsigned offset stored at `pos`.
fn follow(buf: []const u8, pos: usize) Error!usize {
    const off = try readInt(u32, buf, pos);
    const target = @as(u64, pos) + off;
    if (target >= buf.len) return error.Malformed;
    return @intCast(target);
}

/// The table the buffer's root offset points to.
pub fn root(buf: []const u8) Error!Table {
    return Table.at(buf, try follow(buf, 0));
}

pub const Table = struct {
    buf: []const u8,
    pos: usize,
    vt: usize,
    vt_len: u16,
    tbl_len: u16,

    pub fn at(buf: []const u8, pos: usize) Error!Table {
        const soff = try readInt(i32, buf, pos);
        const vt_i: i64 = @as(i64, @intCast(pos)) - soff;
        if (vt_i < 0 or vt_i >= buf.len) return error.Malformed;
        const vt: usize = @intCast(vt_i);
        const vt_len = try readInt(u16, buf, vt);
        const tbl_len = try readInt(u16, buf, vt + 2);
        if (vt_len < 4 or vt_len % 2 != 0 or buf.len - vt < vt_len) return error.Malformed;
        if (tbl_len < 4 or buf.len - pos < tbl_len) return error.Malformed;
        return .{ .buf = buf, .pos = pos, .vt = vt, .vt_len = vt_len, .tbl_len = tbl_len };
    }

    /// The field's position, or null when the vtable does not list it.
    fn field(t: Table, id: u16, size: usize) Error!?usize {
        const slot = 4 + @as(usize, id) * 2;
        if (slot + 2 > t.vt_len) return null;
        const off = try readInt(u16, t.buf, t.vt + slot);
        if (off == 0) return null;
        if (off < 4 or @as(usize, off) + size > t.tbl_len) return error.Malformed;
        return t.pos + off;
    }

    pub fn scalar(t: Table, comptime T: type, id: u16, default: T) Error!T {
        const p = try t.field(id, @sizeOf(T)) orelse return default;
        return readScalar(T, t.buf, p);
    }

    pub fn has(t: Table, id: u16) Error!bool {
        return (try t.field(id, 0)) != null;
    }

    pub fn table(t: Table, id: u16) Error!?Table {
        const p = try t.field(id, 4) orelse return null;
        return try Table.at(t.buf, try follow(t.buf, p));
    }

    pub fn string(t: Table, id: u16) Error!?[]const u8 {
        const p = try t.field(id, 4) orelse return null;
        return try readString(t.buf, try follow(t.buf, p));
    }

    pub fn vector(t: Table, id: u16) Error!?Vector {
        const p = try t.field(id, 4) orelse return null;
        return try Vector.at(t.buf, try follow(t.buf, p));
    }

    /// An inline struct field's bytes.
    pub fn structBytes(t: Table, id: u16, size: usize) Error!?[]const u8 {
        const p = try t.field(id, size) orelse return null;
        return t.buf[p..][0..size];
    }
};

fn readString(buf: []const u8, pos: usize) Error![]const u8 {
    const len = try readInt(u32, buf, pos);
    const start = pos + 4;
    if (buf.len - start < @as(u64, len) + 1) return error.Malformed; // the bytes and the trailing NUL
    return buf[start..][0..len];
}

pub const Vector = struct {
    buf: []const u8,
    /// First element.
    pos: usize,
    len: u32,

    fn at(buf: []const u8, pos: usize) Error!Vector {
        const len = try readInt(u32, buf, pos);
        if (buf.len - pos - 4 < len) return error.Malformed; // at least one byte per element; checked per element below
        return .{ .buf = buf, .pos = pos + 4, .len = len };
    }

    fn elem(v: Vector, i: usize, size: usize) Error!usize {
        if (i >= v.len) return error.Malformed;
        const p = @as(u64, v.pos) + @as(u64, i) * size;
        if (p + size > v.buf.len) return error.Malformed;
        return @intCast(p);
    }

    pub fn scalarAt(v: Vector, comptime T: type, i: usize) Error!T {
        return readScalar(T, v.buf, try v.elem(i, @sizeOf(T)));
    }

    pub fn tableAt(v: Vector, i: usize) Error!Table {
        return Table.at(v.buf, try follow(v.buf, try v.elem(i, 4)));
    }

    pub fn stringAt(v: Vector, i: usize) Error![]const u8 {
        return readString(v.buf, try follow(v.buf, try v.elem(i, 4)));
    }

    /// The bytes of struct element `i` (`size` bytes each).
    pub fn structAt(v: Vector, i: usize, size: usize) Error![]const u8 {
        const p = try v.elem(i, size);
        return v.buf[p..][0..size];
    }
};

// ── builder ─────────────────────────────────────────────────────────────────

/// A reference to something already built: its distance from the END of the
/// buffer (stable while the buffer grows toward the front).
pub const Ref = u32;

pub const Builder = struct {
    gpa: std.mem.Allocator,
    /// The bytes live in `buf[head..]`.
    buf: []u8 = &.{},
    head: usize = 0,
    min_align: usize = 1,
    /// Field id -> distance from the end of the buffer, for the open table.
    slots: [max_fields]Ref = undefined,
    nslots: u16 = 0,
    table_start: Ref = 0,
    in_table: bool = false,

    pub const max_fields = 32;

    pub fn init(gpa: std.mem.Allocator) Builder {
        return .{ .gpa = gpa };
    }

    pub fn deinit(b: *Builder) void {
        b.gpa.free(b.buf);
        b.* = undefined;
    }

    fn size(b: *const Builder) Ref {
        return @intCast(b.buf.len - b.head);
    }

    fn ensure(b: *Builder, n: usize) error{OutOfMemory}!void {
        if (b.head >= n) return;
        const used = b.buf.len - b.head;
        const new_cap = @max(64, (b.buf.len + n) * 2);
        if (new_cap > std.math.maxInt(u32)) return error.OutOfMemory; // offsets are u32
        const nb = try b.gpa.alloc(u8, new_cap);
        @memcpy(nb[new_cap - used ..], b.buf[b.head..]);
        b.gpa.free(b.buf);
        b.buf = nb;
        b.head = new_cap - used;
    }

    fn pad(b: *Builder, n: usize) error{OutOfMemory}!void {
        try b.ensure(n);
        b.head -= n;
        @memset(b.buf[b.head..][0..n], 0);
    }

    /// Pads so that after `additional` more bytes the size is a multiple of `alignment`.
    fn prep(b: *Builder, alignment: usize, additional: usize) error{OutOfMemory}!void {
        b.min_align = @max(b.min_align, alignment);
        const s = @as(usize, b.size()) + additional;
        const p = (alignment - (s % alignment)) % alignment;
        try b.pad(p);
    }

    fn pushBytes(b: *Builder, bytes: []const u8) error{OutOfMemory}!void {
        try b.ensure(bytes.len);
        b.head -= bytes.len;
        @memcpy(b.buf[b.head..][0..bytes.len], bytes);
    }

    fn pushInt(b: *Builder, comptime T: type, v: T) error{OutOfMemory}!void {
        var tmp: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &tmp, v, .little);
        try b.pushBytes(&tmp);
    }

    fn rawScalar(b: *Builder, comptime T: type, v: T) error{OutOfMemory}!void {
        switch (@typeInfo(T)) {
            .int => try b.pushInt(T, v),
            .bool => try b.pushInt(u8, @intFromBool(v)),
            .float => |f| try b.pushInt(std.meta.Int(.unsigned, f.bits), @bitCast(v)),
            .@"enum" => |e| try b.pushInt(e.tag_type, @backingInt(v)),
            else => @compileError("fb: no scalar writer for " ++ @typeName(T)),
        }
    }

    fn pushOffset(b: *Builder, target: Ref) error{OutOfMemory}!void {
        try b.prep(4, 4);
        try b.pushInt(u32, b.size() + 4 - target);
    }

    pub fn createString(b: *Builder, s: []const u8) error{OutOfMemory}!Ref {
        std.debug.assert(!b.in_table);
        if (s.len > std.math.maxInt(u32) - 8) return error.OutOfMemory;
        try b.prep(4, s.len + 1);
        try b.pad(1); // NUL
        try b.pushBytes(s);
        try b.pushInt(u32, @intCast(s.len));
        return b.size();
    }

    /// A vector of scalars.
    pub fn createVector(b: *Builder, comptime T: type, items: []const T) error{OutOfMemory}!Ref {
        std.debug.assert(!b.in_table);
        const es = if (T == bool) 1 else @sizeOf(T);
        try b.prep(4, es * items.len);
        try b.prep(es, es * items.len);
        var i = items.len;
        while (i > 0) {
            i -= 1;
            try b.rawScalar(T, items[i]);
        }
        try b.pushInt(u32, @intCast(items.len));
        return b.size();
    }

    /// A vector of inline structs, given as `n` records of `elem_size` bytes, aligned to `alignment`.
    pub fn createStructVector(b: *Builder, bytes: []const u8, elem_size: usize, alignment: usize) error{OutOfMemory}!Ref {
        std.debug.assert(!b.in_table and bytes.len % elem_size == 0);
        try b.prep(4, bytes.len);
        try b.prep(alignment, bytes.len);
        try b.pushBytes(bytes);
        try b.pushInt(u32, @intCast(bytes.len / elem_size));
        return b.size();
    }

    /// A vector of offsets (tables or strings).
    pub fn createOffsetVector(b: *Builder, refs: []const Ref) error{OutOfMemory}!Ref {
        std.debug.assert(!b.in_table);
        try b.prep(4, 4 * refs.len);
        var i = refs.len;
        while (i > 0) {
            i -= 1;
            try b.pushOffset(refs[i]);
        }
        try b.pushInt(u32, @intCast(refs.len));
        return b.size();
    }

    pub fn startTable(b: *Builder) void {
        std.debug.assert(!b.in_table);
        b.in_table = true;
        b.nslots = 0;
        @memset(&b.slots, 0);
        b.table_start = b.size();
    }

    fn mark(b: *Builder, id: u16) void {
        std.debug.assert(b.in_table and id < max_fields);
        b.slots[id] = b.size();
        b.nslots = @max(b.nslots, id + 1);
    }

    /// A scalar field; skipped when it equals `default` (the reader returns the default).
    pub fn addScalar(b: *Builder, id: u16, comptime T: type, v: T, default: T) error{OutOfMemory}!void {
        if (v == default) return;
        try b.addScalarForce(id, T, v);
    }

    pub fn addScalarForce(b: *Builder, id: u16, comptime T: type, v: T) error{OutOfMemory}!void {
        const s = if (T == bool) 1 else @sizeOf(T);
        try b.prep(s, s);
        try b.rawScalar(T, v);
        b.mark(id);
    }

    pub fn addOffset(b: *Builder, id: u16, target: Ref) error{OutOfMemory}!void {
        try b.pushOffset(target);
        b.mark(id);
    }

    pub fn addStruct(b: *Builder, id: u16, bytes: []const u8, alignment: usize) error{OutOfMemory}!void {
        try b.prep(alignment, bytes.len);
        try b.pushBytes(bytes);
        b.mark(id);
    }

    pub fn endTable(b: *Builder) error{OutOfMemory}!Ref {
        std.debug.assert(b.in_table);
        try b.prep(4, 4);
        try b.pushInt(i32, 0); // soffset to the vtable, patched below
        const obj = b.size();
        const tbl_len = obj - b.table_start;
        if (tbl_len > std.math.maxInt(u16)) return error.OutOfMemory;
        // vtable: [vt_len u16][tbl_len u16][field offsets u16...], written back to front
        var i: usize = b.nslots;
        while (i > 0) {
            i -= 1;
            const off: u16 = if (b.slots[i] == 0) 0 else @intCast(obj - b.slots[i]);
            try b.pushInt(u16, off);
        }
        try b.pushInt(u16, @intCast(tbl_len));
        try b.pushInt(u16, @intCast(4 + 2 * @as(usize, b.nslots)));
        const vt = b.size();
        const table_pos = b.buf.len - obj;
        std.mem.writeInt(i32, b.buf[table_pos..][0..4], @intCast(vt - obj), .little);
        b.in_table = false;
        return obj;
    }

    /// Writes the root offset and returns the finished buffer (owned by the builder until `deinit`).
    pub fn finish(b: *Builder, root_ref: Ref) error{OutOfMemory}![]const u8 {
        std.debug.assert(!b.in_table);
        try b.prep(@max(b.min_align, 8), 4);
        try b.pushOffset(root_ref);
        return b.buf[b.head..];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "builder and reader round trip: scalars with defaults, strings, vectors, nested tables, structs" {
    var b = Builder.init(testing.allocator);
    defer b.deinit();
    const s1 = try b.createString("alpha");
    b.startTable();
    try b.addScalar(0, i64, 42, 0);
    try b.addOffset(1, s1);
    const child = try b.endTable();
    const name = try b.createString("root");
    const nums = try b.createVector(i64, &.{ 1, -2, 3 });
    const kids = try b.createOffsetVector(&.{ child, child });
    var st: [16]u8 = undefined;
    std.mem.writeInt(i64, st[0..8], 7, .little);
    std.mem.writeInt(i64, st[8..16], 9, .little);
    const svec = try b.createStructVector(&st, 16, 8);
    b.startTable();
    try b.addScalar(0, i16, 4, 0);
    try b.addOffset(1, name);
    try b.addOffset(2, nums);
    try b.addOffset(3, kids);
    try b.addScalar(4, bool, true, false);
    try b.addScalar(5, u8, 0, 0); // equal to the default: absent
    try b.addOffset(6, svec);
    try b.addStruct(7, st[0..16], 8);
    const r = try b.endTable();
    const buf = try b.finish(r);

    const t = try root(buf);
    try testing.expectEqual(@as(i16, 4), try t.scalar(i16, 0, 0));
    try testing.expectEqualStrings("root", (try t.string(1)).?);
    const v = (try t.vector(2)).?;
    try testing.expectEqual(@as(u32, 3), v.len);
    try testing.expectEqual(@as(i64, -2), try v.scalarAt(i64, 1));
    const k = (try t.vector(3)).?;
    const c0 = try k.tableAt(1);
    try testing.expectEqual(@as(i64, 42), try c0.scalar(i64, 0, 0));
    try testing.expectEqualStrings("alpha", (try c0.string(1)).?);
    try testing.expect(try t.scalar(bool, 4, false));
    try testing.expect(!try t.has(5));
    try testing.expectEqual(@as(u8, 77), try t.scalar(u8, 5, 77));
    const sv = (try t.vector(6)).?;
    try testing.expectEqual(@as(i64, 9), std.mem.readInt(i64, (try sv.structAt(0, 16))[8..16], .little));
    try testing.expectEqual(@as(i64, 7), std.mem.readInt(i64, (try t.structBytes(7, 16)).?[0..8], .little));
    try testing.expect((try t.table(9)) == null); // past the vtable: absent
    try testing.expectError(error.Malformed, k.tableAt(2));
}

test "reader: every truncation and every single-byte corruption of a buffer is an error or a value, never a crash" {
    var b = Builder.init(testing.allocator);
    defer b.deinit();
    const s = try b.createString("field-name");
    const nums = try b.createVector(i32, &.{ 5, 6, 7, 8 });
    b.startTable();
    try b.addOffset(0, s);
    try b.addOffset(1, nums);
    try b.addScalar(2, i64, -9, 0);
    const r = try b.endTable();
    const good = try b.finish(r);

    const walk = struct {
        fn f(buf: []const u8) void {
            const t = root(buf) catch return;
            _ = t.string(0) catch {};
            if (t.vector(1) catch null) |v| {
                var i: usize = 0;
                while (i < @min(v.len, 16)) : (i += 1) _ = v.scalarAt(i32, i) catch {};
            }
            _ = t.scalar(i64, 2, 0) catch {};
            _ = t.table(1) catch {};
        }
    }.f;
    for (0..good.len) |n| walk(good[0..n]);
    var copy: [256]u8 = undefined;
    for (0..good.len) |i| {
        for ([_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xff }) |val| {
            @memcpy(copy[0..good.len], good);
            copy[i] = val;
            walk(copy[0..good.len]);
        }
    }
}
