// SPDX-License-Identifier: MIT

//! The external anchor: Apache Arrow's integration golden files
//! (apache/arrow-testing, `data/arrow-ipc-stream/integration/`, written by Arrow
//! C++; Apache-2.0, see `../NOTICE`). Each set is a `.stream`, an `.arrow_file`
//! and the Arrow integration JSON (`.json.gz`) describing the same data. Every
//! set this module reads is compared FIELD BY FIELD and CELL BY CELL with its
//! JSON, through an oracle written here from the integration JSON's own
//! encoding (time units, decimal scales, hex binary, dictionary indices,
//! offsets), not through the reader's code. Then: the stream and the file read
//! equal, each file batch is the JSON batch's length, and the frame written
//! back by this module (plain, zstd- and lz4-compressed, stream and file) reads equal.
//! A Map reads as a list of its entries struct. The sets with types `dataframe`
//! has no column for are `error.Unsupported`,
//! with and without `ReadOptions.lossy`.

const std = @import("std");
const df = @import("dataframe");
const stream = @import("stream.zig");
const st = @import("stream_test.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;
const J = std.json.Value;

const v1 = "testdata/1.0.0-littleendian/generated_";
const v2 = "testdata/2.0.0-compression/generated_";
const c21 = "testdata/cpp-21.0.0/generated_";
const v4 = "testdata/4.0.0-shareddict/generated_";

const Want = enum {
    /// Reads with the default options; every cell matches the JSON.
    exact,
    /// `error.Unsupported` by default; with `lossy` every cell matches the JSON, the
    /// values `dataframe` cannot hold (and zones it does not know) as the option says.
    lossy,
};

const Set = struct {
    name: []const u8,
    stream: []const u8,
    file: ?[]const u8,
    json: []const u8,
    want: Want = .exact,
};

fn set(comptime dir: []const u8, comptime name: []const u8, comptime file: bool, want: Want) Set {
    return .{
        .name = name,
        .stream = @embedFile(dir ++ name ++ ".stream"),
        .file = if (file) @embedFile(dir ++ name ++ ".arrow_file") else null,
        .json = @embedFile(dir ++ name ++ ".json.gz"),
        .want = want,
    };
}

const sets = [_]Set{
    set(v1, "custom_metadata", true, .exact),
    set(v1, "dictionary", true, .exact),
    set(v1, "dictionary_unsigned", true, .exact),
    set(v1, "duplicate_fieldnames", true, .exact),
    set(v1, "extension", true, .exact),
    set(v1, "nested", true, .exact),
    set(v1, "nested_large_offsets", true, .exact),
    set(v1, "null", true, .exact),
    set(v1, "null_trivial", true, .exact),
    set(v1, "primitive", true, .exact),
    set(v1, "primitive_large_offsets", true, .exact),
    set(v1, "primitive_no_batches", true, .exact),
    set(v1, "primitive_zerolength", true, .exact),
    set(v1, "recursive_nested", true, .exact),
    // Time32 86400 s (24:00:00); zones `tz` may not know.
    set(v1, "datetime", true, .lossy),
    // Decimal128 up to precision 38 at scale 2: beyond i128 at 12 digits. Its
    // `.arrow_file` (250 KB) is not committed.
    set(v1, "decimal", false, .lossy),
    set(v2, "zstd", true, .exact),
    set(v2, "uncompressible_zstd", true, .exact),
    // LZ4_FRAME bodies (each buffer one LZ4 frame, as Arrow C++ writes it).
    set(v2, "lz4", true, .exact),
    set(v2, "uncompressible_lz4", true, .exact),
    // Decimal32 / Decimal64 (precision 3..9 / 3..18, scale 2) widen exactly.
    set(c21, "decimal32", true, .exact),
    set(c21, "decimal64", true, .exact),
    // Decimal256 of precision 37..69 at scale 5: past 38 digits at 12, so lossy.
    set(c21, "decimal256", true, .lossy),
    // RunEndEncoded (Int16/32/64 run ends over int32, utf8, float32, bool), expanded.
    set(c21, "run_end_encoded", true, .exact),
    // BinaryView / Utf8View (inline and in variadic buffers) and ListView / LargeListView.
    set(c21, "binary_view", true, .exact),
    set(c21, "list_view", true, .exact),
    // Map, read as a list of its entries struct; `map_non_canonical` names the entries,
    // key and value fields otherwise (kept as the file names them).
    set(v1, "map", true, .exact),
    set(v1, "map_non_canonical", true, .exact),
    // A list dictionary whose items are dictionary-encoded, a struct dictionary whose two
    // fields share one: plain list / struct columns of categoricals.
    set(v1, "nested_dictionary", true, .exact),
    // Two columns sharing one dictionary.
    set(v4, "shared_dict", true, .exact),
};

/// Sets with a type `dataframe` has no column for: only their `.stream` is committed.
const refused = [_]struct { []const u8, []const u8 }{
    .{ "interval", @embedFile(v1 ++ "interval.stream") },
    .{ "union", @embedFile(v1 ++ "union.stream") },
};

fn gunzip(a: Allocator, gz: []const u8) ![]u8 {
    var in: std.Io.Reader = .fixed(gz);
    const window = try a.alloc(u8, std.compress.flate.max_window_len);
    var dec = std.compress.flate.Decompress.init(&in, .gzip, window);
    return dec.reader.allocRemaining(a, .limited(64 << 20));
}

// ── the JSON side ───────────────────────────────────────────────────────────

fn get(v: J, key: []const u8) ?J {
    return switch (v) {
        .object => |o| o.get(key),
        else => null,
    };
}

fn str(v: J, key: []const u8) []const u8 {
    return get(v, key).?.string;
}

fn items(v: J, key: []const u8) []const J {
    return if (get(v, key)) |x| x.array.items else &.{};
}

/// An integer as the integration JSON writes it: a number, or a decimal string for
/// 64-bit and wider values.
fn jint(v: J) !i128 {
    return switch (v) {
        .integer => |i| i,
        .string, .number_string => |s| std.fmt.parseInt(i128, s, 10),
        else => error.TestUnexpectedJson,
    };
}

/// A Decimal256 value (up to 77 digits).
fn jint256(v: J) !i256 {
    return switch (v) {
        .integer => |i| i,
        .string, .number_string => |s| std.fmt.parseInt(i256, s, 10),
        else => error.TestUnexpectedJson,
    };
}

fn jfloat(v: J) !f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .string, .number_string => |s| std.fmt.parseFloat(f64, s),
        else => error.TestUnexpectedJson,
    };
}

fn typeName(field: J) []const u8 {
    return str(get(field, "type").?, "name");
}

/// Microseconds per unit, as a signed power of ten (`NANOSECOND`: divide by 1000).
fn unitExp(unit: []const u8) i8 {
    if (std.mem.eql(u8, unit, "SECOND")) return 6;
    if (std.mem.eql(u8, unit, "MILLISECOND")) return 3;
    if (std.mem.eql(u8, unit, "MICROSECOND")) return 0;
    return -3;
}

/// `x` units as microseconds (nanoseconds truncated toward zero, as `lossy` reads them),
/// or null past i64.
fn micros(x: i128, unit: []const u8) ?i64 {
    const e = unitExp(unit);
    const us: i128 = if (e >= 0) x * std.math.pow(i128, 10, @intCast(e)) else @divTrunc(x, 1000);
    return std.math.cast(i64, us);
}

/// Proleptic Gregorian civil date of a day count since 1970-01-01 (H. Hinnant's
/// `civil_from_days`), formatted `YYYY-MM-DD`, or null outside the years 0000-9999.
fn isoDay(buf: *[10]u8, days: i128) ?[]const u8 {
    const z = days + 719_468;
    const era = @divFloor(z, 146_097);
    const doe = z - era * 146_097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36_524) - @divFloor(doe, 146_096), 365);
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const y = yoe + era * 400 + @as(i128, if (m <= 2) 1 else 0);
    if (y < 0 or y > 9999) return null;
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ @as(u32, @intCast(y)), @as(u32, @intCast(m)), @as(u32, @intCast(d)) }) catch unreachable;
}

/// A raw Decimal128 at `scale` as `dataframe`'s 12-digit i128, or null when inexact or
/// out of range.
fn decimal12(raw: i128, scale: i64) ?i128 {
    const k = 12 - scale;
    if (k >= 0) {
        if (k > 38) return if (raw == 0) 0 else null;
        return std.math.mul(i128, raw, std.math.pow(i128, 10, @intCast(k))) catch null;
    }
    if (-k > 38) return if (raw == 0) 0 else null;
    const p = std.math.pow(i128, 10, @intCast(-k));
    if (@rem(raw, p) != 0) return null;
    return @divExact(raw, p);
}

fn zoneKnown(z: []const u8) bool {
    const c: df.Column = .{ .name = "", .type = .timestamp, .time_zone = z };
    c.checkZone() catch return false;
    return true;
}

const Oracle = struct {
    json: J,
    lossy: bool,
    /// Where a mismatch is reported: set name, column, row.
    where: []const u8 = "",
    row: usize = 0,

    fn dictColumn(o: *const Oracle, id: i128) !J {
        for (items(o.json, "dictionaries")) |d| {
            if (try jint(get(d, "id").?) == id) return items(get(d, "data").?, "columns")[0];
        }
        return error.TestMissingDictionary;
    }

    fn fail(o: *const Oracle, field: J, comptime fmt: []const u8, args: anytype) error{TestExpectedEqual} {
        std.debug.print("golden {s}: field {s} row {d}: ", .{ o.where, str(field, "name"), o.row });
        std.debug.print(fmt ++ "\n", args);
        return error.TestExpectedEqual;
    }

    /// The column `dataframe` declares for a field: name, type, zone, width, inner columns.
    fn expectColumn(o: *const Oracle, field: J, col: df.Column) !void {
        return o.expectColumnNamed(field, col, str(field, "name"));
    }

    fn expectColumnNamed(o: *const Oracle, field: J, col: df.Column, want_name: []const u8) anyerror!void {
        if (!std.mem.eql(u8, want_name, col.name)) return o.fail(field, "name {s}", .{col.name});
        const t = get(field, "type").?;
        const name = str(t, "name");
        // A run-end encoded column reads as a plain column of its values' type.
        if (std.mem.eql(u8, name, "runendencoded")) return o.expectColumnNamed(items(field, "children")[1], col, want_name);
        const dict_text = get(field, "dictionary") != null and (std.mem.eql(u8, name, "utf8") or std.mem.eql(u8, name, "largeutf8") or std.mem.eql(u8, name, "utf8view"));
        const want: df.ColumnType = if (dict_text) .categorical else if (std.mem.eql(u8, name, "int")) blk: {
            const bits = try jint(get(t, "bitWidth").?);
            const signed = get(t, "isSigned").?.bool;
            break :blk switch (bits) {
                8 => if (signed) .int8 else .uint8,
                16 => if (signed) .int16 else .uint16,
                32 => if (signed) .int32 else .uint32,
                else => if (signed) .int else .uint64,
            };
        } else if (std.mem.eql(u8, name, "floatingpoint"))
            (if (std.mem.eql(u8, str(t, "precision"), "DOUBLE")) .float else .float32)
        else if (std.mem.eql(u8, name, "bool")) .bool else if (std.mem.eql(u8, name, "utf8") or std.mem.eql(u8, name, "largeutf8") or std.mem.eql(u8, name, "utf8view") or std.mem.eql(u8, name, "null"))
            .text
        else if (std.mem.eql(u8, name, "binary") or std.mem.eql(u8, name, "largebinary") or std.mem.eql(u8, name, "fixedsizebinary") or std.mem.eql(u8, name, "binaryview"))
            .binary
        else if (std.mem.eql(u8, name, "listview") or std.mem.eql(u8, name, "largelistview"))
            .list
        else if (std.mem.eql(u8, name, "decimal")) .decimal else if (std.mem.eql(u8, name, "date")) .date else if (std.mem.eql(u8, name, "time")) .time else if (std.mem.eql(u8, name, "timestamp")) .timestamp else if (std.mem.eql(u8, name, "duration")) .duration else if (std.mem.eql(u8, name, "list") or std.mem.eql(u8, name, "largelist") or std.mem.eql(u8, name, "map")) .list else if (std.mem.eql(u8, name, "fixedsizelist")) .array else if (std.mem.eql(u8, name, "struct")) .@"struct" else return o.fail(field, "type {s} not in the mapping", .{name});
        if (col.type != want) return o.fail(field, "type {t}, want {t}", .{ col.type, want });
        if (want == .timestamp) {
            const zone: ?[]const u8 = if (get(t, "timezone")) |z| z.string else null;
            const kept: ?[]const u8 = if (zone) |z| (if (zoneKnown(z)) z else if (o.lossy) null else return o.fail(field, "unknown zone {s} read without lossy", .{z})) else null;
            if (kept) |z| {
                if (col.time_zone == null or !std.mem.eql(u8, z, col.time_zone.?)) return o.fail(field, "zone {?s}, want {s}", .{ col.time_zone, z });
            } else if (col.time_zone != null) return o.fail(field, "zone {s}, want none", .{col.time_zone.?});
        }
        if (want == .array and col.array_width != try jint(get(t, "listSize").?)) return o.fail(field, "width {d}", .{col.array_width});
        if (want == .list or want == .array or want == .@"struct") {
            const kids = items(field, "children");
            if (kids.len != col.inner.len) return o.fail(field, "{d} inner columns", .{col.inner.len});
            if (std.mem.eql(u8, name, "map")) return o.expectMapEntries(kids[0], col.inner[0]);
            for (kids, col.inner) |k, c| try o.expectColumn(k, c);
        }
    }

    /// A Map's entries struct. The reader keeps the names the file gives; Arrow C++ writes
    /// the canonical `entries` / `key` / `value` whatever the JSON says (the
    /// `map_non_canonical` `.stream`; its `.arrow_file` keeps the JSON's names), so either
    /// is the file's own.
    fn expectMapEntries(o: *const Oracle, entries: J, col: df.Column) !void {
        try o.expectNameOr(entries, col, "entries");
        if (col.type != .@"struct" or col.inner.len != 2) return o.fail(entries, "type {t} of {d}", .{ col.type, col.inner.len });
        for (items(entries, "children"), col.inner, [_][]const u8{ "key", "value" }) |k, c, canonical| {
            try o.expectNameOr(k, c, canonical);
            try o.expectColumnNamed(k, c, c.name);
        }
    }

    fn expectNameOr(o: *const Oracle, field: J, col: df.Column, canonical: []const u8) !void {
        if (!std.mem.eql(u8, col.name, str(field, "name")) and !std.mem.eql(u8, col.name, canonical)) return o.fail(field, "name {s}", .{col.name});
    }

    /// Cell `i` of the JSON column `cj` (of `field`) against the frame's cell.
    fn expectCell(o: *const Oracle, field: J, cj: J, i: usize, got: df.Value, use_dict: bool) anyerror!void {
        const vals = items(cj, "VALIDITY");
        const valid = vals.len == 0 or try jint(vals[i]) != 0;
        if (!valid) return o.expectNull(field, got);
        if (use_dict) if (get(field, "dictionary")) |d| {
            const idx = try jint(items(cj, "DATA")[i]);
            const dcol = try o.dictColumn(try jint(get(d, "id").?));
            return o.expectCell(field, dcol, @intCast(idx), got, false);
        };
        const t = get(field, "type").?;
        const name = str(t, "name");
        const data = items(cj, "DATA");
        if (std.mem.eql(u8, name, "runendencoded")) {
            // Row i is the value of the first run whose end exceeds i.
            const kids = items(field, "children");
            const kc = items(cj, "children");
            const run = for (items(kc[0], "DATA"), 0..) |e, j| {
                if (try jint(e) > i) break j;
            } else return o.fail(field, "row past the last run end", .{});
            return o.expectCell(kids[1], kc[1], run, got, true);
        }
        if (std.mem.eql(u8, name, "utf8view") or std.mem.eql(u8, name, "binaryview")) {
            // A view: inline (`INLINED`, text or hex) or `SIZE` bytes at `OFFSET` of the hex
            // variadic buffer `BUFFER_INDEX`.
            const v = items(cj, "VIEWS")[i];
            const size: usize = @intCast(try jint(get(v, "SIZE").?));
            const is_text = std.mem.eql(u8, name, "utf8view");
            var buf: [4096]u8 = undefined;
            const want: []const u8 = if (size <= 12) blk: {
                const s = str(v, "INLINED");
                break :blk if (is_text) s else try std.fmt.hexToBytes(&buf, s);
            } else blk: {
                const hex = items(cj, "VARIADIC_DATA_BUFFERS")[@intCast(try jint(get(v, "BUFFER_INDEX").?))].string;
                const off: usize = @intCast(try jint(get(v, "OFFSET").?));
                break :blk try std.fmt.hexToBytes(&buf, hex[2 * off ..][0 .. 2 * size]);
            };
            if (got != .text or !std.mem.eql(u8, got.text, want)) return o.fail(field, "{any}, want {s}", .{ got, want });
            return;
        }
        if (std.mem.eql(u8, name, "listview") or std.mem.eql(u8, name, "largelistview")) {
            const lo: usize = @intCast(try jint(items(cj, "OFFSET")[i]));
            const size: usize = @intCast(try jint(items(cj, "SIZE")[i]));
            if (got != .list or got.list.len() != size) return o.fail(field, "{any}, want a list of {d}", .{ got, size });
            for (lo..lo + size, 0..) |e, k| try o.expectCell(items(field, "children")[0], items(cj, "children")[0], e, got.list.get(k), true);
            return;
        }
        if (std.mem.eql(u8, name, "null")) return o.expectNull(field, got);
        if (std.mem.eql(u8, name, "bool")) {
            if (got != .bool or got.bool != data[i].bool) return o.fail(field, "{any}, want {}", .{ got, data[i].bool });
            return;
        }
        if (std.mem.eql(u8, name, "int")) {
            const want = try jint(data[i]);
            const have: ?i128 = switch (got) {
                .int => |x| x,
                .uint => |x| x,
                else => null,
            };
            if (have != want) return o.fail(field, "{any}, want {d}", .{ got, want });
            return;
        }
        if (std.mem.eql(u8, name, "floatingpoint")) {
            const want = try jfloat(data[i]);
            if (got != .float) return o.fail(field, "{any}, want {d}", .{ got, want });
            const prec = str(t, "precision");
            const same = if (std.mem.eql(u8, prec, "DOUBLE"))
                got.float == want
            else if (std.mem.eql(u8, prec, "SINGLE"))
                @as(f32, @floatCast(got.float)) == @as(f32, @floatCast(want))
            else
                @as(f16, @floatCast(got.float)) == @as(f16, @floatCast(want));
            if (!same) return o.fail(field, "{d}, want {d}", .{ got.float, want });
            return;
        }
        if (std.mem.eql(u8, name, "utf8") or std.mem.eql(u8, name, "largeutf8")) {
            if (got != .text or !std.mem.eql(u8, got.text, data[i].string)) return o.fail(field, "{any}, want \"{s}\"", .{ got, data[i].string });
            return;
        }
        if (std.mem.eql(u8, name, "binary") or std.mem.eql(u8, name, "largebinary") or std.mem.eql(u8, name, "fixedsizebinary")) {
            var buf: [256]u8 = undefined;
            const want = try std.fmt.hexToBytes(&buf, data[i].string);
            if (got != .text or !std.mem.eql(u8, got.text, want)) return o.fail(field, "{any}, want {s}", .{ got, data[i].string });
            return;
        }
        if (std.mem.eql(u8, name, "decimal")) {
            const wide = try jint256(data[i]);
            // More digits than the declared precision is not a value of the type.
            const prec: u8 = @intCast(try jint(get(t, "precision").?));
            if (@abs(wide) >= std.math.pow(u256, 10, prec)) return o.unholdable(field, got);
            // A Decimal256 outside i128 has no `dataframe` form.
            const raw = std.math.cast(i128, wide) orelse return o.unholdable(field, got);
            const want = decimal12(raw, @intCast(try jint(get(t, "scale").?))) orelse return o.unholdable(field, got);
            // 39 digits at scale 12 fit an i128 but no Decimal128 (38 digits at most).
            if (@abs(want) >= std.math.pow(u128, 10, 38)) return o.unholdable(field, got);
            if (got != .decimal or got.decimal != want) return o.fail(field, "{any}, want {d}", .{ got, want });
            return;
        }
        if (std.mem.eql(u8, name, "date")) {
            const raw = try jint(data[i]);
            const days = if (std.mem.eql(u8, str(t, "unit"), "DAY")) raw else @divFloor(raw, 86_400_000);
            var buf: [10]u8 = undefined;
            const want = isoDay(&buf, days) orelse return o.unholdable(field, got);
            if (got != .text or !std.mem.eql(u8, got.text, want)) return o.fail(field, "{any}, want {s}", .{ got, want });
            return;
        }
        if (std.mem.eql(u8, name, "time") or std.mem.eql(u8, name, "timestamp") or std.mem.eql(u8, name, "duration")) {
            const want = micros(try jint(data[i]), str(t, "unit")) orelse return o.unholdable(field, got);
            if (std.mem.eql(u8, name, "time") and (want < 0 or want >= 86_400_000_000)) return o.unholdable(field, got);
            if (got != .int or got.int != want) return o.fail(field, "{any}, want {d}", .{ got, want });
            return;
        }
        if (std.mem.eql(u8, name, "list") or std.mem.eql(u8, name, "largelist") or std.mem.eql(u8, name, "map") or std.mem.eql(u8, name, "fixedsizelist")) {
            const child = items(field, "children")[0];
            const ccol = items(cj, "children")[0];
            var lo: usize = undefined;
            var hi: usize = undefined;
            if (std.mem.eql(u8, name, "fixedsizelist")) {
                const w: usize = @intCast(try jint(get(t, "listSize").?));
                lo = i * w;
                hi = lo + w;
            } else {
                const offs = items(cj, "OFFSET");
                lo = @intCast(try jint(offs[i]));
                hi = @intCast(try jint(offs[i + 1]));
            }
            if (got != .list or got.list.len() != hi - lo) return o.fail(field, "{any}, want a list of {d}", .{ got, hi - lo });
            for (lo..hi, 0..) |e, k| try o.expectCell(child, ccol, e, got.list.get(k), true);
            return;
        }
        if (std.mem.eql(u8, name, "struct")) {
            const kids = items(field, "children");
            if (got != .record or got.record.len() != kids.len) return o.fail(field, "{any}, want a record of {d}", .{ got, kids.len });
            for (kids, items(cj, "children"), 0..) |k, kc, ki| try o.expectCell(k, kc, i, got.record.get(ki), true);
            return;
        }
        return o.fail(field, "type {s} not in the oracle", .{name});
    }

    fn expectNull(o: *const Oracle, field: J, got: df.Value) !void {
        if (got != .null) return o.fail(field, "{any}, want null", .{got});
    }

    /// A value `dataframe` cannot hold: null under `lossy`; without it the read must
    /// have failed, so reaching here is a mismatch.
    fn unholdable(o: *const Oracle, field: J, got: df.Value) !void {
        if (!o.lossy) return o.fail(field, "{any} for a value dataframe cannot hold", .{got});
        return o.expectNull(field, got);
    }

    /// The whole frame against the JSON: the columns, then every batch's cells at its rows.
    fn expectFrame(o: *Oracle, f: df.Frame) !void {
        const fields = items(get(o.json, "schema").?, "fields");
        try testing.expectEqual(fields.len, f.columns.len);
        for (fields, f.columns) |fj, c| try o.expectColumn(fj, c);
        var base: usize = 0;
        for (items(o.json, "batches")) |b| {
            const n: usize = @intCast(try jint(get(b, "count").?));
            for (fields, items(b, "columns"), 0..) |fj, cj, ci| {
                for (0..n) |i| {
                    o.row = base + i;
                    try o.expectCell(fj, cj, i, f.columnAt(ci).get(base + i), true);
                }
            }
            base += n;
        }
        try testing.expectEqual(base, f.len);
    }
};

/// The same key/value pairs; the order is not compared (Arrow C++ writes an extension
/// type's pairs in another order than its JSON lists them).
fn expectKeyValues(want: []const J, got: []const stream.KeyValue) !void {
    try testing.expectEqual(want.len, got.len);
    for (want) |w| {
        const n = for (got) |g| {
            if (std.mem.eql(u8, str(w, "key"), g.key)) break g;
        } else return error.TestMissingKey;
        try testing.expectEqualStrings(str(w, "value"), n.value);
    }
}

/// The children of the column a JSON field reads as: a run-end encoded field's are
/// its `values` field's (the `run_ends` / `values` fields themselves are not columns).
fn columnChildren(field: J) []const J {
    const kids = items(field, "children");
    if (std.mem.eql(u8, typeName(field), "runendencoded")) return columnChildren(kids[1]);
    return kids;
}

/// The fields' key/value metadata (`metadata` in the JSON), recursively, in the shape
/// of the frame's columns; with `names` the field names too (a frame written back names
/// a list's child `item`; a Map's entries, key and value may carry their canonical names,
/// see `Oracle.expectMapEntries`).
fn expectFieldMetadata(fields: []const J, got: []const stream.FieldMetadata, names: bool) !void {
    return expectFieldMetadataIn(fields, got, names, &.{});
}

fn expectFieldMetadataIn(fields: []const J, got: []const stream.FieldMetadata, names: bool, canonical: []const []const u8) !void {
    try testing.expectEqual(fields.len, got.len);
    for (fields, got, 0..) |fj, g, i| {
        if (names and !(i < canonical.len and std.mem.eql(u8, canonical[i], g.name))) try testing.expectEqualStrings(str(fj, "name"), g.name);
        try expectKeyValues(items(fj, "metadata"), g.metadata);
        const kids_canonical: []const []const u8 = if (std.mem.eql(u8, typeName(fj), "map")) &.{"entries"} else if (canonical.len == 1) &.{ "key", "value" } else &.{};
        try expectFieldMetadataIn(columnChildren(fj), g.children, names, kids_canonical);
    }
}

fn expectMetadata(json: J, md: stream.Metadata, names: bool) !void {
    const sch = get(json, "schema").?;
    try expectKeyValues(items(sch, "metadata"), md.schema);
    try expectFieldMetadata(items(sch, "fields"), md.fields, names);
}

/// A projected read `p` against the full read `full`: the columns `refs` picked (by
/// index), in that order, cell for cell.
fn expectProjected(full: df.Frame, p: df.Frame, refs: []const stream.ColumnRef) !void {
    var cols: [64]df.Column = undefined;
    var data: [64]df.ColumnData = undefined;
    for (refs, 0..) |x, k| {
        cols[k] = full.columns[x.index];
        data[k] = full.columnAt(x.index);
    }
    try st.expectSameFrame(.{ .columns = cols[0..refs.len], .data = data[0..refs.len], .len = full.len }, p);
}

test "golden: apache/arrow-testing integration files read field by field equal to their JSON" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    for (sets) |s| {
        _ = arena_state.reset(.retain_capacity);
        const a = arena_state.allocator();
        const json = try std.json.parseFromSliceLeaky(J, a, try gunzip(a, s.json), .{});
        const lossy = s.want == .lossy;
        if (lossy) try testing.expectError(error.Unsupported, stream.readStream(a, s.stream, .{}));
        var md: stream.Metadata = .{};
        const opts: stream.ReadOptions = .{ .lossy = lossy, .metadata = &md };
        var o: Oracle = .{ .json = json, .lossy = lossy, .where = s.name };

        const f = try stream.readStream(a, s.stream, opts);
        try o.expectFrame(f);
        // Schema and field key/value metadata (`custom_metadata`, `extension`).
        try expectMetadata(json, md, true);

        if (s.file) |bytes| {
            var fmd: stream.Metadata = .{};
            var fopts = opts;
            fopts.metadata = &fmd;
            try st.expectSameFrame(f, try stream.readFile(a, bytes, fopts));
            try expectMetadata(json, fmd, true);
            var file = try stream.openFile(a, bytes, opts);
            const batches = items(json, "batches");
            try testing.expectEqual(batches.len, file.batchCount());
            for (batches, 0..) |b, i| {
                const n: usize = @intCast(try jint(get(b, "count").?));
                try testing.expectEqual(n, file.batchRows(i));
                try testing.expectEqual(n, (try file.readBatch(i)).len);
            }
        }

        // Projection: the columns in reverse order, then each alone, read as the full
        // frame's (stream and file).
        {
            const n = f.columns.len;
            const refs = try a.alloc(stream.ColumnRef, n);
            for (refs, 0..) |*x, i| x.* = .{ .index = n - 1 - i };
            var popts: stream.ReadOptions = .{ .lossy = lossy, .columns = refs };
            try expectProjected(f, try stream.readStream(a, s.stream, popts), refs);
            if (s.file) |bytes| try expectProjected(f, try stream.readFile(a, bytes, popts), refs);
            for (0..n) |i| {
                const one = [_]stream.ColumnRef{.{ .index = i }};
                popts.columns = &one;
                try expectProjected(f, try stream.readStream(a, s.stream, popts), &one);
                if (s.file) |bytes| try expectProjected(f, try stream.readFile(a, bytes, popts), &one);
            }
        }

        // What this module writes of the frame and of its metadata reads back equal,
        // plain and compressed (a run-end encoded field is written back plain, a Map as a
        // List of its entries struct: the metadata read has the frame's shape either way).
        for ([_]stream.Compression{ .none, .zstd, .lz4 }) |c| {
            const wo: stream.WriteOptions = .{ .compression = c, .rows_per_batch = 8, .schema_metadata = md.schema, .field_metadata = md.fields };
            for ([_]bool{ false, true }) |file| {
                var bmd: stream.Metadata = .{};
                const back = if (file) try stream.writeFile(gpa, f, wo) else try stream.writeStream(gpa, f, wo);
                defer gpa.free(back);
                const g = if (file) try stream.readFile(a, back, .{ .metadata = &bmd }) else try stream.readStream(a, back, .{ .metadata = &bmd });
                try st.expectSameFrame(f, g);
                try expectMetadata(json, bmd, false);
            }
        }
    }
}

test "golden: the sets with types dataframe has no column for are Unsupported, lossy or not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    for (refused) |r| {
        for ([_]bool{ false, true }) |lossy| {
            _ = arena_state.reset(.retain_capacity);
            if (stream.readStream(arena_state.allocator(), r[1], .{ .lossy = lossy })) |_| {
                std.debug.print("golden {s}: read without error\n", .{r[0]});
                return error.TestExpectedError;
            } else |e| if (e != error.Unsupported) {
                std.debug.print("golden {s}: {t}\n", .{ r[0], e });
                return e;
            }
        }
    }
}
