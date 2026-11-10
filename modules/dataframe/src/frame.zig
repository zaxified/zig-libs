// SPDX-License-Identifier: MIT
//! `Frame`, the columnar table: one typed array per column, built by `FrameBuilder` or
//! by hand. Taken from `dataset`'s `Frame` (the same authors, MIT): a frame built here
//! from the same cells has the same arrays, bitmaps and storage kinds as one built
//! there, which `storage_test.zig` checks cell by cell and array by array.
//!
//! **Physical storage follows the cells, not the declared `ColumnType`.** A column
//! declared `.float` may hold `.int` cells or a mix: all cells of one `Value` tag (or
//! null) get that tag's array, a mix gets `.boxed`, a plain `[]Value`. `.date` stays
//! text and `.timestamp` stays int.

const std = @import("std");
const vm = @import("value.zig");
const Value = vm.Value;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const dtype = @import("dtype.zig");

/// One typed column's cells. A null cell holds 0 in `values`, and `valid` has its
/// bit clear; `valid == null` means no cell is null. NaN is a value, not a null.
pub fn TypedColumn(comptime T: type) type {
    return struct {
        const Self = @This();
        values: []const T,
        /// Bit `i % 64` of word `i / 64` set: row `i` is not null.
        valid: ?[]const u64 = null,

        /// Row `row` is present and not null.
        pub inline fn isValid(self: Self, row: usize) bool {
            if (row >= self.values.len) return false;
            const v = self.valid orelse return true;
            const w = row / 64;
            return w < v.len and (v[w] >> @intCast(row % 64)) & 1 == 1;
        }
    };
}

/// Text cells: row `i` is `bytes[offsets[i]..offsets[i + 1]]`. A null cell is empty
/// and has its `valid` bit clear, so it differs from an empty string.
pub const TextColumn = struct {
    offsets: []const usize,
    bytes: []const u8,
    valid: ?[]const u64 = null,

    pub inline fn isValid(self: TextColumn, row: usize) bool {
        if (row >= self.offsets.len -| 1) return false;
        const v = self.valid orelse return true;
        const w = row / 64;
        return w < v.len and (v[w] >> @intCast(row % 64)) & 1 == 1;
    }

    /// Row `row`'s text; null if it is null or past the end.
    pub inline fn at(self: TextColumn, row: usize) ?[]const u8 {
        if (!self.isValid(row)) return null;
        const lo = self.offsets[row];
        const hi = self.offsets[row + 1];
        if (lo > hi or hi > self.bytes.len) return null;
        return self.bytes[lo..hi];
    }
};

/// A dictionary-encoded text column (`ColumnType.categorical`'s storage): row `i` is
/// `dict.at(codes.values[i])`, null where `codes` has its bit clear. `dict` holds each
/// distinct value once, in lexical byte order, with no null, so a code compares as its
/// text does (pandas' `cat.codes`). Columns of one frame may share a `dict`.
pub const CatColumn = struct {
    codes: TypedColumn(u32),
    dict: TextColumn,
    /// Whether the dictionary's order means something (pandas `ordered`, polars `Enum`): an
    /// ordered column compares by code in `Expr` (`<`, `>`), and every categorical sorts by
    /// code. The dictionary is then the caller's, in the caller's order, and may hold
    /// categories no row uses (`catfn.zig`); `encodeCategorical` still makes a lexical,
    /// unordered one from the observed values.
    ordered: bool = false,

    pub inline fn at(self: CatColumn, row: usize) ?[]const u8 {
        if (!self.codes.isValid(row)) return null;
        return self.dict.at(self.codes.values[row]);
    }
};

/// A list column (`ColumnType.list`'s storage, Arrow's list layout): row `i` is elements
/// `offsets[i]..offsets[i + 1]` of `items`, null where `valid` has its bit clear (a null
/// row's two offsets are equal). All rows' elements are one column, so `items` holds at
/// most `maxInt(u32)` of them.
pub const ListColumn = struct {
    offsets: []const u32,
    items: *const ColumnData,
    valid: ?[]const u64 = null,

    pub inline fn isValid(self: ListColumn, row: usize) bool {
        if (row >= self.offsets.len -| 1) return false;
        const v = self.valid orelse return true;
        const w = row / 64;
        return w < v.len and (v[w] >> @intCast(row % 64)) & 1 == 1;
    }

    /// Row `row`'s elements; null if it is null, past the end, or its offsets run backwards.
    /// Offsets past the stored elements are cut to them (a hand-built column claiming 2^32
    /// elements over three made every walker loop that long); `.nulls` elements have no
    /// stored length, as a list of null elements is legitimately stored.
    pub inline fn at(self: ListColumn, row: usize) ?vm.ListView {
        if (!self.isValid(row)) return null;
        var lo = self.offsets[row];
        var hi = self.offsets[row + 1];
        if (lo > hi) return null;
        if (self.items.storedLen()) |n| {
            const cap: u32 = @intCast(@min(n, std.math.maxInt(u32)));
            lo = @min(lo, cap);
            hi = @min(hi, cap);
        }
        return .{ .items = self.items, .start = lo, .end = hi };
    }
};

/// A struct column (`ColumnType.@"struct"`'s storage, Arrow's struct layout): one child
/// column per field, row `i` of each is the field of row `i`; `len` rows. The field names
/// live here, so a `Value.record` names its fields without the schema. A null row has its
/// `valid` bit clear (its children's cells there are null).
pub const StructColumn = struct {
    names: []const []const u8,
    /// One per name; a child missing (a hand-built column) reads as null.
    children: []const ColumnData,
    len: usize,
    valid: ?[]const u64 = null,

    pub inline fn isValid(self: StructColumn, row: usize) bool {
        if (row >= self.len) return false;
        const v = self.valid orelse return true;
        const w = row / 64;
        return w < v.len and (v[w] >> @intCast(row % 64)) & 1 == 1;
    }
};

pub const ColumnData = union(enum) {
    /// Every cell is null, or there are no rows. No storage.
    nulls,
    int: TypedColumn(i64),
    float: TypedColumn(f64),
    bool: TypedColumn(bool),
    decimal: TypedColumn(i128),
    text: TextColumn,
    /// Text, dictionary-encoded (`CatColumn`); its cells are `Value.text`.
    categorical: CatColumn,
    /// Lists (`ListColumn`); its cells are `Value.list`.
    list: ListColumn,
    /// Records (`StructColumn`, behind a pointer so a `Value.record` can point at it);
    /// its cells are `Value.record`.
    @"struct": *const StructColumn,
    /// Cells of more than one `Value` tag.
    boxed: []const Value,
    /// The fixed-width numbers (wave W11): a column declared `.int8`..`.float32` holds one
    /// of these (`conform`). Cells read as `Value.int` (`Value.uint` for a UInt64 above
    /// `maxInt(i64)`) and `Value.float`, widened exactly.
    int8: TypedColumn(i8),
    int16: TypedColumn(i16),
    int32: TypedColumn(i32),
    uint8: TypedColumn(u8),
    uint16: TypedColumn(u16),
    uint32: TypedColumn(u32),
    uint64: TypedColumn(u64),
    float32: TypedColumn(f32),

    /// The rows the storage holds, or null for `.nulls` (no storage, any length). A hand-built
    /// column may hold fewer or more than its frame's `len`; `get` reads a missing row as null.
    pub fn storedLen(self: ColumnData) ?usize {
        return switch (self) {
            .nulls => null,
            .int => |x| x.values.len,
            .float => |x| x.values.len,
            .bool => |x| x.values.len,
            .decimal => |x| x.values.len,
            .text => |x| x.offsets.len -| 1,
            .categorical => |x| x.codes.values.len,
            .list => |x| x.offsets.len -| 1,
            .@"struct" => |x| x.len,
            .boxed => |x| x.len,
            inline .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 => |x| x.values.len,
        };
    }

    /// The cell at `row` as a `Value`. A row past the end reads as `.null`. `.text`,
    /// `.list` and `.record` borrow from the column.
    pub inline fn get(self: ColumnData, row: usize) Value {
        switch (self) {
            .nulls => return .null,
            .int => |c| return if (c.isValid(row)) .{ .int = c.values[row] } else .null,
            .float => |c| return if (c.isValid(row)) .{ .float = c.values[row] } else .null,
            .bool => |c| return if (c.isValid(row)) .{ .bool = c.values[row] } else .null,
            .decimal => |c| return if (c.isValid(row)) .{ .decimal = c.values[row] } else .null,
            .text => |c| return if (c.at(row)) |t| .{ .text = t } else .null,
            .categorical => |c| return if (c.at(row)) |t| .{ .text = t } else .null,
            .list => |c| return if (c.at(row)) |l| .{ .list = l } else .null,
            .@"struct" => |c| return if (c.isValid(row)) .{ .record = .{ .fields = c, .row = row } } else .null,
            .boxed => |c| return if (row < c.len) c[row] else .null,
            inline .int8, .int16, .int32, .uint8, .uint16, .uint32 => |c| return if (c.isValid(row)) .{ .int = c.values[row] } else .null,
            .uint64 => |c| {
                if (!c.isValid(row)) return .null;
                const u = c.values[row];
                return if (u <= std.math.maxInt(i64)) .{ .int = @intCast(u) } else .{ .uint = u };
            },
            .float32 => |c| return if (c.isValid(row)) .{ .float = c.values[row] } else .null,
        }
    }
};

/// `col` stored as the width type `ty` declares (`ColumnType.int8`..`.float32`): its own
/// array, each cell converted exactly; a cell that is not a value of `ty` (out of range, a
/// fraction, another kind) is null. Any other `ty`, or storage already of that kind, comes
/// back as it is. The verbs range-check before they store, so the null here is a guard:
/// whatever a hand-built or mixed column holds, the declared width and the array agree.
pub fn conform(a: std.mem.Allocator, col: ColumnData, ty: ColumnType, len: usize) std.mem.Allocator.Error!ColumnData {
    return switch (ty) {
        inline .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 => |t| blk: {
            if (std.meta.activeTag(col) == @field(std.meta.Tag(ColumnData), @tagName(t))) break :blk col;
            if (col == .nulls) break :blk col;
            const T = switch (t) {
                .float32 => f32,
                else => dtype.IntOf(t),
            };
            const values = try a.alloc(T, len);
            var valid: ?[]u64 = null;
            var present: usize = 0;
            for (values, 0..) |*o, ri| {
                const v = col.get(ri);
                const got: ?T = if (T == f32) (if (v.asFloat()) |f| @as(f32, @floatCast(f)) else null) else if (dtype.exactI128(v)) |x| std.math.cast(T, x) else null;
                if (got) |g| {
                    o.* = g;
                    present += 1;
                    continue;
                }
                o.* = 0;
                if (valid == null) {
                    const bitmap = try a.alloc(u64, (len + 63) / 64);
                    @memset(bitmap, ~@as(u64, 0));
                    valid = bitmap;
                }
                valid.?[ri / 64] &= ~(@as(u64, 1) << @intCast(ri % 64));
            }
            // No cell left: no storage, as `ColBuilder` gives every all-null column.
            if (present == 0) {
                a.free(values);
                if (valid) |v| a.free(v);
                break :blk .nulls;
            }
            break :blk @unionInit(ColumnData, @tagName(t), .{ .values = values, .valid = valid });
        },
        // A time of day: Int64 storage of microseconds inside one day (`Value.cast(.time)`
        // converts a float or text cell); anything else null (fuzz seed 457: `map` with
        // `out_type = .time` stored its float results under the time column).
        .time => blk: {
            if (col == .nulls) break :blk col;
            if (col == .int) {
                const ic = col.int;
                const ok = for (ic.values[0..@min(len, ic.values.len)], 0..) |x, ri| {
                    if (ic.isValid(ri) and !vm.isTimeOfDay(x)) break false;
                } else ic.values.len >= len;
                if (ok) break :blk col;
            }
            const cells = try a.alloc(Value, len);
            defer a.free(cells);
            for (cells, 0..) |*o, ri| o.* = col.get(ri).cast(.time) orelse .null;
            break :blk try columnFromCells(a, cells);
        },
        else => col,
    };
}

/// Whether every column declared with a width type holds that width's array (or no
/// storage): what `conform` makes true. For tests and the fuzz harness.
pub fn widthsConform(f: Frame) bool {
    for (f.columns, 0..) |c, ci| {
        if (!dtype.isWidth(c.type)) continue;
        const d = f.columnAt(ci);
        if (d == .nulls) continue;
        if (!std.mem.eql(u8, @tagName(std.meta.activeTag(d)), @tagName(c.type))) return false;
    }
    return true;
}

/// `v` with the storage it borrows copied into `a` (text and every nested level), so it
/// outlives the column it was read from; a nested value at `depth` past
/// `max_nesting_depth` is null. What a boxed column stores.
pub fn copyValue(a: std.mem.Allocator, v: Value, depth: u8) std.mem.Allocator.Error!Value {
    switch (vm.Value.capped(v, depth)) {
        .text => |t| return .{ .text = try a.dupe(u8, t) },
        .list => |l| {
            var b: ColBuilder = .{ .a = a, .hint = l.len(), .depth = depth + 1 };
            for (0..l.len()) |i| try b.append(l.get(i));
            const items = try a.create(ColumnData);
            items.* = b.finish();
            return .{ .list = .{ .items = items, .start = 0, .end = @intCast(l.len()) } }; // a view's length is a u32 difference
        },
        .record => |r| {
            const names = try a.alloc([]const u8, r.len());
            const children = try a.alloc(ColumnData, r.len());
            for (names, children, 0..) |*n, *c, i| {
                n.* = try a.dupe(u8, r.name(i));
                var b: ColBuilder = .{ .a = a, .hint = 1, .depth = depth + 1 };
                try b.append(r.get(i));
                c.* = b.finish();
            }
            const st = try a.create(StructColumn);
            st.* = .{ .names = names, .children = children, .len = 1 };
            return .{ .record = .{ .fields = st, .row = 0 } };
        },
        else => |x| return x,
    }
}

/// `col` dictionary-encoded (`CatColumn`): the distinct texts once, lexically ordered,
/// one code per row. Its cells must be text or null (the `cast` rule makes them so); any
/// other cell reads as null. A `.categorical` column comes back as it is. The dictionary
/// is copied, so the result does not borrow from `col`. `error.TooLarge` past `u32` rows.
pub fn encodeCategorical(a: std.mem.Allocator, col: ColumnData, len: usize) error{ OutOfMemory, TooLarge }!ColumnData {
    if (col == .categorical or col == .nulls) return col; // no cell: no storage, as everywhere
    if (len > std.math.maxInt(u32)) return error.TooLarge;
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    defer map.deinit(a);
    var distinct: std.ArrayList([]const u8) = .empty;
    defer distinct.deinit(a);
    const codes = try a.alloc(u32, len);
    var valid: ?[]u64 = null;
    for (codes, 0..) |*code, ri| {
        const v = col.get(ri);
        if (v != .text) {
            code.* = 0;
            if (valid == null) {
                const bits = try a.alloc(u64, (len + 63) / 64);
                @memset(bits, ~@as(u64, 0));
                valid = bits;
            }
            valid.?[ri / 64] &= ~(@as(u64, 1) << @intCast(ri % 64));
            continue;
        }
        const gop = try map.getOrPut(a, v.text);
        if (!gop.found_existing) {
            gop.value_ptr.* = @intCast(distinct.items.len);
            try distinct.append(a, v.text);
        }
        code.* = gop.value_ptr.*;
    }
    // Codes by first appearance → codes by lexical rank.
    const n = distinct.items.len;
    const order = try a.alloc(u32, n);
    defer a.free(order);
    for (order, 0..) |*o, i| o.* = @intCast(i);
    const Ctx = struct {
        texts: []const []const u8,
        fn lessThan(c: @This(), x: u32, y: u32) bool {
            return std.mem.order(u8, c.texts[x], c.texts[y]) == .lt;
        }
    };
    std.sort.pdq(u32, order, Ctx{ .texts = distinct.items }, Ctx.lessThan);
    const rank = try a.alloc(u32, n);
    defer a.free(rank);
    var total: usize = 0;
    for (order, 0..) |o, k| {
        rank[o] = @intCast(k);
        total += distinct.items[o].len;
    }
    const offsets = try a.alloc(usize, n + 1);
    const bytes = try a.alloc(u8, total);
    var at: usize = 0;
    for (order, 0..) |o, k| {
        offsets[k] = at;
        const t = distinct.items[o];
        @memcpy(bytes[at..][0..t.len], t);
        at += t.len;
    }
    offsets[n] = at;
    if (n != 0) {
        for (codes, 0..) |*code, ri| {
            if (valid) |bits| if ((bits[ri / 64] >> @intCast(ri % 64)) & 1 == 0) continue;
            code.* = rank[code.*];
        }
    }
    return .{ .categorical = .{
        .codes = .{ .values = codes, .valid = valid },
        .dict = .{ .offsets = offsets, .bytes = bytes },
    } };
}

/// `f` with every column declared `.categorical` dictionary-encoded (the readers type a
/// column, then store it as text) and every width column in its own array (`conform`). The frame's arrays are reused, its `data` replaced.
pub fn encodeDeclared(a: std.mem.Allocator, f: Frame) error{ OutOfMemory, TooLarge }!Frame {
    var any = false;
    for (f.columns) |c| any = any or c.type == .categorical or dtype.isWidth(c.type);
    if (!any) return f;
    const data = try a.alloc(ColumnData, f.columns.len);
    for (data, f.columns, 0..) |*d, c, ci| {
        d.* = f.columnAt(ci);
        if (c.type == .categorical) d.* = try encodeCategorical(a, d.*, f.len);
        d.* = try conform(a, d.*, c.type, f.len);
    }
    return .{ .columns = f.columns, .data = data, .len = f.len };
}

/// One column's storage from its cells, the array their tags call for. Text is copied.
pub fn columnFromCells(a: std.mem.Allocator, cells: []const Value) std.mem.Allocator.Error!ColumnData {
    var b: ColBuilder = .{ .a = a, .hint = cells.len };
    for (cells) |c| try b.append(c);
    return b.finish();
}

/// A child for an `ArenaAllocator` that holds big frames: a block of 2 MiB or more comes
/// aligned to that, everything else is `page_allocator`. A fresh arena's 4 KiB page faults
/// are most of what a columnar verb costs on a big table: measured in `tabular`'s bench,
/// `mutate` over 1 M rows 2.47 to 0.82x pandas with huge pages.
///
/// Huge pages come two ways. With `transparent_hugepage/enabled = always` the kernel gives
/// an aligned block huge pages by itself. The block is advised `MADV_HUGEPAGE` only where
/// `transparent_hugepage/defrag` is `defer` or `never`: under `always`, `madvise` (the
/// usual distribution default) and `defer+madvise` the advice makes every fault in the block
/// compact memory directly, and on a fragmented host that stalls. Measured 2026-11-08
/// (31 GB, 4 GB free, `enabled=madvise`, `defrag=madvise`): 1 GiB touched through an
/// advised arena took 2.1-5.6 s against 0.54-0.61 s for `page_allocator`, with 2472
/// compaction stalls, every one failed, and 822 of 1024 huge-page faults falling back
/// anyway; up to 3.9 s for one 0.2 s verb on 2026-11-04. The setting is read once, on the
/// first big block. Off Linux, or where it cannot be read, no advice. Safe from any thread.
pub const big_block_allocator: std.mem.Allocator = .{ .ptr = undefined, .vtable = &big_block_vtable };

/// `big_block_allocator` that advises every block of 2 MiB or more `MADV_HUGEPAGE`
/// whatever `transparent_hugepage/defrag` says — numpy's policy, so pandas' (numpy
/// advises its large allocations by default). Faster where huge pages are at hand: the
/// 2026-11-08 bench rows that write big fresh outputs (`cumsum`, `melt`, `concat`,
/// `filter`, `distinct`, joins) ran 1.1-3x faster with it on the bench host. On a
/// fragmented host under `defrag=madvise` it is the stall `big_block_allocator`'s
/// comment measures (2.1-5.6 s for 1 GiB against 0.55 s). The choice is the caller's:
/// long-lived batch jobs on a host with free memory gain, latency-bound services risk
/// the stall. Safe from any thread.
pub const huge_page_allocator: std.mem.Allocator = .{ .ptr = undefined, .vtable = &huge_page_vtable };

const big_block_size = 2 * 1024 * 1024;

const big_block_vtable: std.mem.Allocator.VTable = .{
    .alloc = bigBlockAlloc,
    .resize = std.mem.Allocator.noResize,
    .remap = std.mem.Allocator.noRemap,
    .free = bigBlockFree,
};

const huge_page_vtable: std.mem.Allocator.VTable = .{
    .alloc = hugePageAlloc,
    .resize = std.mem.Allocator.noResize,
    .remap = std.mem.Allocator.noRemap,
    .free = bigBlockFree,
};

fn bigBlockAlloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
    return blockAlloc(len, alignment, ret, false);
}

fn hugePageAlloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
    return blockAlloc(len, alignment, ret, true);
}

fn blockAlloc(len: usize, alignment: std.mem.Alignment, ret: usize, always_advise: bool) ?[*]u8 {
    const pa = std.heap.page_allocator; // global-alloc-ok: this IS an allocator, over the OS's pages
    if (len < big_block_size) return pa.rawAlloc(len, alignment, ret);
    // The page allocator adds the alignment to the length unchecked.
    if (len > std.math.maxInt(usize) - 2 * big_block_size) return null;
    const al = std.mem.Alignment.fromByteUnits(@max(alignment.toByteUnits(), big_block_size));
    const p = pa.rawAlloc(len, al, ret) orelse return null;
    if (@import("builtin").os.tag == .linux and (always_advise or adviseHuge())) {
        // Advice only: a refusal leaves ordinary pages.
        _ = std.os.linux.madvise(@alignCast(p), len, std.os.linux.MADV.HUGEPAGE);
    }
    return p;
}

/// 0 = not read yet, 1 = advise, 2 = do not. Racing first readers read the same file.
var huge_advice: std.atomic.Value(u8) = .init(0);

fn adviseHuge() bool {
    switch (huge_advice.load(.monotonic)) {
        1 => return true,
        2 => return false,
        else => {},
    }
    // `/sys/kernel/mm/transparent_hugepage/defrag` by raw syscalls: an allocator has no
    // `Io` to hand. Unreadable means no advice.
    const linux = std.os.linux;
    var buf: [128]u8 = undefined;
    var n: usize = 0;
    const rc = linux.open("/sys/kernel/mm/transparent_hugepage/defrag", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) == .SUCCESS) {
        const fd: linux.fd_t = @intCast(rc);
        const got = linux.read(fd, &buf, buf.len);
        if (linux.errno(got) == .SUCCESS) n = got;
        _ = linux.close(fd);
    }
    const ok = defragWithoutDirectCompaction(buf[0..n]);
    huge_advice.store(if (ok) 1 else 2, .monotonic);
    return ok;
}

/// Whether the selected `defrag` value (the bracketed word, e.g.
/// `always defer defer+madvise [madvise] never`) leaves a `MADV_HUGEPAGE` fault without
/// direct compaction: only `defer` and `never` do.
pub fn defragWithoutDirectCompaction(setting: []const u8) bool {
    const open = std.mem.indexOfScalar(u8, setting, '[') orelse return false;
    const close = std.mem.indexOfScalarPos(u8, setting, open, ']') orelse return false;
    const sel = setting[open + 1 .. close];
    return std.mem.eql(u8, sel, "defer") or std.mem.eql(u8, sel, "never");
}

fn bigBlockFree(_: *anyopaque, mem: []u8, alignment: std.mem.Alignment, ret: usize) void {
    // The alignment the block was allocated with: a big one got `big_block_size`.
    const al = if (mem.len < big_block_size) alignment else std.mem.Alignment.fromByteUnits(@max(alignment.toByteUnits(), big_block_size));
    std.heap.page_allocator.rawFree(mem, al, ret); // global-alloc-ok: see bigBlockAlloc
}

/// Column name -> position, built once, for a verb that looks up many names: a
/// `Frame.columnIndex` per name is quadratic in the width, and a `pivot` or a `transpose`
/// makes frames of millions of columns. Of equal names the first wins, as `columnIndex`.
pub const NameIndex = struct {
    map: std.StringHashMapUnmanaged(usize) = .empty,
    columns: []const Column = &.{},

    pub fn init(a: std.mem.Allocator, columns: []const Column) std.mem.Allocator.Error!NameIndex {
        var idx: NameIndex = .{ .columns = columns };
        errdefer idx.map.deinit(a);
        try idx.map.ensureTotalCapacity(a, @intCast(@min(columns.len, std.math.maxInt(u32))));
        for (columns, 0..) |c, i| {
            const gop = idx.map.getOrPutAssumeCapacity(c.name);
            if (!gop.found_existing) gop.value_ptr.* = i;
        }
        return idx;
    }

    pub fn deinit(self: *NameIndex, a: std.mem.Allocator) void {
        self.map.deinit(a);
    }

    pub fn get(self: NameIndex, name: []const u8) ?usize {
        return self.map.get(name);
    }

    pub fn must(self: NameIndex, name: []const u8) error{NoSuchColumn}!usize {
        return self.map.get(name) orelse error.NoSuchColumn;
    }
};

pub const FrameBuilderError = error{ OutOfMemory, RowLength };

/// Most rows `FrameBuilder.init`'s `expected_rows` reserves for up front.
pub const max_row_hint: usize = 1 << 20;

/// A table as one typed array per column. Immutable, and allocated from an arena the
/// caller frees at once: the arrays may be longer than `len` behind the slices'
/// capacity, so a general-purpose allocator would leak them. Build one with
/// `FrameBuilder` or by hand; a hand-built one with arrays shorter than `len`, or
/// fewer `data` entries than `columns`, reads as null past their end.
///
/// Rows have no labels (polars' model, not pandas' index): a row is its position.
pub const Frame = struct {
    columns: []const Column,
    data: []const ColumnData,
    len: usize,

    /// Index of the column named `name`, or null.
    pub fn columnIndex(self: Frame, name: []const u8) ?usize {
        for (self.columns, 0..) |c, i| {
            if (std.mem.eql(u8, c.name, name)) return i;
        }
        return null;
    }

    pub fn columnType(self: Frame, name: []const u8) ?ColumnType {
        const i = self.columnIndex(name) orelse return null;
        return self.columns[i].type;
    }

    pub fn rowCount(self: Frame) usize {
        return self.len;
    }

    /// The cell at (row, column-name), or null if the column is absent or `row` is
    /// past the last row. A column with no array (a hand-built frame with fewer `data`
    /// entries than `columns`) is all null, as every verb reads it.
    pub fn cell(self: Frame, row: usize, name: []const u8) ?Value {
        const i = self.columnIndex(name) orelse return null;
        if (row >= self.len) return null;
        return self.columnAt(i).get(row);
    }

    /// The column's storage, or null if there is no such column; `.nulls` for a column
    /// with no array.
    pub fn column(self: Frame, name: []const u8) ?ColumnData {
        const i = self.columnIndex(name) orelse return null;
        return self.columnAt(i);
    }

    /// The storage of column `ci`; a position past `data` (a hand-built frame) reads as
    /// all null.
    pub inline fn columnAt(self: Frame, ci: usize) ColumnData {
        return if (ci < self.data.len) self.data[ci] else .nulls;
    }

    /// One column as a `Series`, or null if there is no such column.
    pub fn series(self: Frame, name: []const u8) ?Series {
        const i = self.columnIndex(name) orelse return null;
        return .{ .name = self.columns[i].name, .type = self.columns[i].type, .data = self.columnAt(i), .len = self.len, .time_zone = self.columns[i].time_zone };
    }

    /// A numeric column as `[]f64`, non-numeric and null read as 0. **Borrows the frame's array when every cell
    /// is `.float` (no allocation)**, otherwise allocates from `a`. The borrowed array
    /// relies on a null cell holding 0, which only a hand-built frame can break.
    pub fn floatColumn(self: Frame, a: std.mem.Allocator, name: []const u8) ![]const f64 {
        const col = self.column(name) orelse return error.NoSuchColumn;
        if (col == .float and col.float.values.len == self.len) return col.float.values;
        const out = try a.alloc(f64, self.len);
        for (out, 0..) |*x, ri| x.* = col.get(ri).asFloat() orelse 0;
        return out;
    }

    /// Two columns as an owned `[][2]f64` series: a non-numeric x reads as the row
    /// index, a non-numeric y as 0.
    pub fn seriesXY(self: Frame, a: std.mem.Allocator, x: []const u8, y: []const u8) ![]const [2]f64 {
        const xc = self.column(x) orelse return error.NoSuchColumn;
        const yc = self.column(y) orelse return error.NoSuchColumn;
        const out = try a.alloc([2]f64, self.len);
        for (out, 0..) |*p, ri| {
            p.* = .{ xc.get(ri).asFloat() orelse @as(f64, @floatFromInt(ri)), yc.get(ri).asFloat() orelse 0 };
        }
        return out;
    }
};

/// One column under construction. Starts with no storage; the first non-null cell
/// picks the array, the first cell of another tag moves everything to `.boxed`.
/// One column's cells appended in row order, stored in the array their tags call for
/// (`columnFromCells` and the readers). Internal: not re-exported from the root.
pub const ColBuilder = struct {
    a: std.mem.Allocator,
    /// Rows expected, the capacity reserved when the array is picked. `deserializeFrame`
    /// passes a count the input has proved.
    hint: usize,
    /// Most text bytes to reserve up front. A decoder passes its column's share of
    /// the input: the whole of it per column let 1000 columns of 2 MB reserve 1 GB.
    text_cap: usize = 1 << 20,
    kind: Kind = .nulls,
    len: usize = 0,
    has_null: bool = false,
    ints: std.ArrayList(i64) = .empty,
    floats: std.ArrayList(f64) = .empty,
    bools: std.ArrayList(bool) = .empty,
    decimals: std.ArrayList(i128) = .empty,
    offsets: std.ArrayList(usize) = .empty,
    bytes: std.ArrayList(u8) = .empty,
    boxed: std.ArrayList(Value) = .empty,
    valid: std.ArrayList(u64) = .empty,
    /// Levels below the column: a nested cell at `max_nesting_depth` is stored as null.
    depth: u8 = 0,
    /// `.list`: the offsets, the elements' builder and the slot `finish` puts their storage in.
    list_offsets: std.ArrayList(u32) = .empty,
    items: ?*ColBuilder = null,
    items_data: ?*ColumnData = null,
    /// `.record`: one builder per field and the storage `finish` fills.
    fields: []ColBuilder = &.{},
    st: ?*StructColumn = null,
    field_data: []ColumnData = &.{},

    const Kind = enum { nulls, int, float, bool, decimal, text, list, record, boxed };

    fn pick(s: *ColBuilder, k: Kind, first: Value) std.mem.Allocator.Error!void {
        const cap = @max(s.hint, s.len +| 1);
        // Every cell so far was null: zeros in the array, and clear bits.
        switch (k) {
            .int => try s.ints.appendNTimes(s.a, 0, s.len),
            .float => try s.floats.appendNTimes(s.a, 0, s.len),
            .bool => try s.bools.appendNTimes(s.a, false, s.len),
            .decimal => try s.decimals.appendNTimes(s.a, 0, s.len),
            .text => try s.offsets.appendNTimes(s.a, 0, s.len + 1),
            .list => {
                try s.list_offsets.appendNTimes(s.a, 0, s.len + 1);
                const ib = try s.a.create(ColBuilder);
                ib.* = .{ .a = s.a, .hint = 0, .depth = s.depth + 1 };
                s.items = ib;
                s.items_data = try s.a.create(ColumnData);
            },
            .record => {
                const r = first.record;
                const names = try s.a.alloc([]const u8, r.len());
                for (names, 0..) |*n, i| n.* = try s.a.dupe(u8, r.name(i));
                s.fields = try s.a.alloc(ColBuilder, r.len());
                for (s.fields) |*fb| {
                    // The column's text reservation is shared by its fields, as by a frame's columns.
                    fb.* = .{ .a = s.a, .hint = s.hint, .text_cap = s.text_cap / @max(1, r.len()), .depth = s.depth + 1 };
                    for (0..s.len) |_| try fb.appendNull();
                }
                s.field_data = try s.a.alloc(ColumnData, r.len());
                const st = try s.a.create(StructColumn);
                st.* = .{ .names = names, .children = s.field_data, .len = 0 };
                s.st = st;
            },
            .nulls, .boxed => unreachable,
        }
        switch (k) {
            .int => try s.ints.ensureTotalCapacity(s.a, cap),
            .float => try s.floats.ensureTotalCapacity(s.a, cap),
            .bool => try s.bools.ensureTotalCapacity(s.a, cap),
            .decimal => try s.decimals.ensureTotalCapacity(s.a, cap),
            .text => try s.offsets.ensureTotalCapacity(s.a, cap +| 1),
            .list => try s.list_offsets.ensureTotalCapacity(s.a, cap +| 1),
            .record => {},
            .nulls, .boxed => unreachable,
        }
        if (s.len > 0) {
            s.has_null = true;
            try s.valid.appendNTimes(s.a, 0, s.len / 64 + 1);
        }
        s.kind = k;
    }

    /// Every cell so far, as `Value`s. Text stays in `bytes`, which is not freed.
    fn toBoxed(s: *ColBuilder) std.mem.Allocator.Error!void {
        try s.boxed.ensureTotalCapacity(s.a, @max(s.hint, s.len +| 1));
        const col = s.finish();
        for (0..s.len) |ri| s.boxed.appendAssumeCapacity(col.get(ri));
        s.kind = .boxed;
    }

    fn setBit(s: *ColBuilder, value: bool) std.mem.Allocator.Error!void {
        const w = s.len / 64;
        while (s.valid.items.len <= w) try s.valid.append(s.a, 0);
        if (value) s.valid.items[w] |= @as(u64, 1) << @intCast(s.len % 64);
    }

    /// A cell of the kind the column already is, into reserved capacity: the common
    /// case, decided in two compares. Anything else goes through `appendSlow`.
    inline fn push(s: *ColBuilder, comptime k: Kind, comptime field: []const u8, x: anytype) std.mem.Allocator.Error!void {
        const list = &@field(s, field);
        if (s.kind == k and list.items.len < list.capacity) {
            list.appendAssumeCapacity(x);
            if (s.has_null) try s.setBit(true);
            s.len += 1;
            return;
        }
        return s.appendSlow(@unionInit(Value, @tagName(k), x));
    }

    inline fn pushText(s: *ColBuilder, x: []const u8) std.mem.Allocator.Error!void {
        if (s.kind == .text and s.offsets.items.len < s.offsets.capacity) {
            try s.bytes.appendSlice(s.a, x);
            s.offsets.appendAssumeCapacity(s.bytes.items.len);
            if (s.has_null) try s.setBit(true);
            s.len += 1;
            return;
        }
        return s.appendSlow(.{ .text = x });
    }

    pub inline fn append(s: *ColBuilder, v: Value) std.mem.Allocator.Error!void {
        switch (v) {
            .null => return s.appendNull(),
            .int => |x| return s.push(.int, "ints", x),
            .float => |x| return s.push(.float, "floats", x),
            .bool => |x| return s.push(.bool, "bools", x),
            .decimal => |x| return s.push(.decimal, "decimals", x),
            .text => |x| return s.pushText(x),
            .list, .record, .uint => return s.appendSlow(v),
        }
    }

    /// Whether record `r` has this struct column's field names, in order. Compared every
    /// time: a source's address says nothing (a caller may reuse one storage per row).
    fn sameFields(s: *const ColBuilder, r: vm.RecordView) bool {
        const names = s.st.?.names;
        if (names.len != r.len()) return false;
        for (names, 0..) |n, i| if (!std.mem.eql(u8, n, r.name(i))) return false;
        return true;
    }

    fn appendSlow(s: *ColBuilder, v: Value) std.mem.Allocator.Error!void {
        // A UInt64 above maxInt(i64) has no array of its own here: the column is boxed
        // (`conform` gives a declared UInt64 its `u64` array).
        if (v == .uint) {
            if (s.kind != .boxed) try s.toBoxed();
            try s.boxed.append(s.a, v);
            s.len += 1;
            return;
        }
        const k: Kind = switch (v) {
            .null, .uint => unreachable,
            .int => .int,
            .float => .float,
            .bool => .bool,
            .decimal => .decimal,
            .text => .text,
            .list => .list,
            .record => .record,
        };
        if ((k == .list or k == .record) and s.depth >= vm.max_nesting_depth) return s.appendNull();
        // Records of other fields are a mix: the column is boxed.
        const fits = s.kind == k and (k != .record or s.sameFields(v.record));
        if (!fits and s.kind != .boxed) {
            if (s.kind == .nulls) {
                try s.pick(k, v);
                // One guess at the column's text from its first cell; a wrong one
                // only costs ordinary growth.
                if (k == .text) try s.bytes.ensureTotalCapacity(s.a, @min(s.text_cap, v.text.len *| s.hint));
            } else try s.toBoxed();
        }
        switch (s.kind) {
            .int => try s.ints.append(s.a, v.int),
            .float => try s.floats.append(s.a, v.float),
            .bool => try s.bools.append(s.a, v.bool),
            .decimal => try s.decimals.append(s.a, v.decimal),
            .text => {
                try s.bytes.appendSlice(s.a, v.text);
                try s.offsets.append(s.a, s.bytes.items.len);
            },
            .list => {
                const ib = s.items.?;
                const l = v.list;
                // The offsets are u32 (Arrow's list): past that many elements in one
                // column there is no storage to grow into.
                if (ib.len + l.len() > std.math.maxInt(u32)) return error.OutOfMemory;
                for (0..l.len()) |i| try ib.append(l.get(i));
                try s.list_offsets.append(s.a, @intCast(ib.len));
            },
            .record => for (s.fields, 0..) |*fb, i| try fb.append(v.record.get(i)),
            // `bytes` and the nested builders stop growing once boxed (the cells `toBoxed`
            // took point into them), so a later cell gets its own copy.
            .boxed => try s.boxed.append(s.a, try copyValue(s.a, v, s.depth)),
            .nulls => unreachable,
        }
        if (s.has_null and s.kind != .boxed) try s.setBit(true);
        s.len += 1;
    }

    pub fn appendNull(s: *ColBuilder) std.mem.Allocator.Error!void {
        switch (s.kind) {
            .nulls => {
                s.len += 1;
                return;
            },
            .boxed => {
                try s.boxed.append(s.a, .null);
                s.len += 1;
                return;
            },
            .int => try s.ints.append(s.a, 0),
            .float => try s.floats.append(s.a, 0),
            .bool => try s.bools.append(s.a, false),
            .decimal => try s.decimals.append(s.a, 0),
            .text => try s.offsets.append(s.a, s.bytes.items.len),
            .list => try s.list_offsets.append(s.a, @intCast(s.items.?.len)),
            .record => for (s.fields) |*fb| try fb.appendNull(),
        }
        if (!s.has_null) {
            // The first null: every earlier row was not.
            s.has_null = true;
            try s.valid.appendNTimes(s.a, ~@as(u64, 0), s.len / 64);
            if (s.len % 64 != 0) try s.valid.append(s.a, (@as(u64, 1) << @intCast(s.len % 64)) - 1);
        }
        try s.setBit(false);
        s.len += 1;
    }

    pub fn finish(s: *const ColBuilder) ColumnData {
        const valid: ?[]const u64 = if (s.has_null) s.valid.items else null;
        return switch (s.kind) {
            .nulls => .nulls,
            .int => .{ .int = .{ .values = s.ints.items, .valid = valid } },
            .float => .{ .float = .{ .values = s.floats.items, .valid = valid } },
            .bool => .{ .bool = .{ .values = s.bools.items, .valid = valid } },
            .decimal => .{ .decimal = .{ .values = s.decimals.items, .valid = valid } },
            .text => .{ .text = .{ .offsets = s.offsets.items, .bytes = s.bytes.items, .valid = valid } },
            .list => blk: {
                s.items_data.?.* = s.items.?.finish();
                break :blk .{ .list = .{ .offsets = s.list_offsets.items, .items = s.items_data.?, .valid = valid } };
            },
            .record => blk: {
                for (s.field_data, s.fields) |*d, *fb| d.* = fb.finish();
                const st = s.st.?;
                st.len = s.len;
                st.valid = valid;
                break :blk .{ .@"struct" = st };
            },
            .boxed => .{ .boxed = s.boxed.items },
        };
    }
};

/// Row-at-a-time construction of a `Frame`. The cells are copied, text included, so
/// the caller's buffers may go after `appendRow` returns. `expected_rows` only
/// reserves capacity; 0 is fine.
pub const FrameBuilder = struct {
    a: std.mem.Allocator,
    columns: []const Column,
    cols: []ColBuilder,
    len: usize = 0,
    /// A failed allocation may have left some columns one cell ahead of the others.
    failed: bool = false,

    pub fn init(a: std.mem.Allocator, columns: []const Column, expected_rows: usize) std.mem.Allocator.Error!FrameBuilder {
        const cols = try a.alloc(ColBuilder, columns.len);
        // A hint is only a reservation: past `max_row_hint` the arrays grow as rows
        // come, so a huge one costs no more than a big one, never an overflow.
        for (cols) |*c| c.* = .{ .a = a, .hint = @min(expected_rows, max_row_hint) };
        return .{ .a = a, .columns = columns, .cols = cols };
    }

    /// `error.RowLength` if `cells.len != columns.len`, and the row is not added.
    /// After `error.OutOfMemory` the builder is spent: this and `toOwned` keep
    /// returning it, rather than giving a table whose columns disagree on the rows.
    pub fn appendRow(self: *FrameBuilder, cells: []const Value) FrameBuilderError!void {
        if (self.failed) return error.OutOfMemory;
        if (cells.len != self.cols.len) return error.RowLength;
        errdefer self.failed = true;
        for (self.cols, cells) |*c, v| try c.append(v);
        self.len += 1;
    }

    /// The frame shares the builder's arrays, so the builder must not be used after
    /// this. A column declared with a width type gets that width's array (`conform`).
    pub fn toOwned(self: *const FrameBuilder) std.mem.Allocator.Error!Frame {
        if (self.failed) return error.OutOfMemory;
        const data = try self.a.alloc(ColumnData, self.cols.len);
        for (data, self.cols, self.columns) |*d, *c, col| d.* = try conform(self.a, c.finish(), col.type, self.len);
        return .{ .columns = self.columns, .data = data, .len = self.len };
    }
};

/// One column of a frame, with its name and length: a view, nothing is copied. Verbs
/// take a `Frame` and column names; a `Series` is for reading one column's cells.
pub const Series = struct {
    name: []const u8,
    type: ColumnType,
    data: ColumnData,
    len: usize,
    /// The column's `time_zone` (null: naive, or not a timestamp).
    time_zone: ?[]const u8 = null,

    /// Cell `row`; past `len` (or past a short hand-built array) it is `.null`.
    pub fn get(self: Series, row: usize) Value {
        return if (row < self.len) self.data.get(row) else .null;
    }

    /// Cells that are null, or a NaN float: the module's one rule for "missing".
    pub fn nullCount(self: Series) usize {
        var n: usize = 0;
        for (0..self.len) |ri| {
            const v = self.data.get(ri);
            n += @intFromBool(v == .null or (v == .float and std.math.isNan(v.float)));
        }
        return n;
    }
};
