// SPDX-License-Identifier: MIT
//! The S2 no-panic sweep, agent B (2026-11-10): the dataframe code added since the D5 sweep in
//! `jsonread csvchunk ndjsonchunk csvio jsonio render textio dtfn frameops more verbs value frame
//! root structure reshape analysis spec core keys`. Each finding's trigger, pinned; then the
//! clean probes (hypotheses that did not crash). Names end "(sweep B-<n>)" or "(sweep B clean probe)".

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const dtf = @import("dtfn.zig");
const cc = @import("csvchunk.zig");
const nc = @import("ndjsonchunk.zig");
const Slow = @import("s2w9_test.zig").Slow;
const tz = @import("tz");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;

// ── B-1: a stream of blank lines grew the chunk text without bound ─────────────────

test "NdjsonChunkReader holds no text for blank lines (sweep B-1)" {
    // A million blank lines and then nothing: the chunk's cap counted bytes minus one per line,
    // so a line of just `\n` added nothing to it, yet the line stayed in the chunk text.
    const blank = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(blank);
    @memset(blank, '\n');
    var slow: Slow = undefined;
    slow.init(blank, 0);
    var rd = nc.NdjsonChunkReader.init(testing.allocator, &slow.interface, .{ .max_bytes = 1024 });
    defer rd.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expect((try rd.next(arena.allocator(), 4)) == null);
    try testing.expect(rd.chunk.capacity <= 1024);
    // Blank and whitespace-only lines between records do not count as rows and are not kept.
    slow.init("\n \n{\"a\":1}\n\r\n\t\n{\"a\":2}\n", 0);
    var rd2 = nc.NdjsonChunkReader.init(testing.allocator, &slow.interface, .{});
    defer rd2.deinit();
    const f = (try rd2.next(arena.allocator(), 2)).?;
    try testing.expectEqual(@as(usize, 2), f.len);
    try testing.expectEqual(@as(i64, 2), f.cell(1, "a").?.int);
    try testing.expectEqualStrings("{\"a\":1}\n{\"a\":2}\n", rd2.chunk.items);
    try testing.expect((try rd2.next(arena.allocator(), 2)) == null);
}

// ── clean probes: the writers over zoned, duration and nested cells ───────────────────

fn col(a: std.mem.Allocator, name: []const u8, ty: df.ColumnType, zone: ?[]const u8, vals: []const i64) !struct { Column, df.ColumnData } {
    return .{
        .{ .name = name, .type = ty, .time_zone = zone },
        .{ .int = .{ .values = try a.dupe(i64, vals), .valid = null } },
    };
}

fn zonedFrame(a: std.mem.Allocator) !Frame {
    const imin = std.math.minInt(i64);
    const imax = std.math.maxInt(i64);
    const stamps = [_]i64{ imin, imin + 1, -62135596800 * 1_000_000, -1, 0, 1, 253402300799 * 1_000_000, 1_700_000_000_123_456, imax - 1, imax };
    const zones = [_]?[]const u8{ "UTC", "Europe/Prague", "Asia/Kolkata", "Pacific/Kiritimati", "America/St_Johns", "Pacific/Chatham", "Australia/Lord_Howe", null };
    var cols: std.ArrayList(Column) = .empty;
    var data: std.ArrayList(df.ColumnData) = .empty;
    for (zones, 0..) |z, i| {
        const c = try col(a, try std.fmt.allocPrint(a, "t{d}", .{i}), .timestamp, z, &stamps);
        try cols.append(a, c[0]);
        try data.append(a, c[1]);
    }
    const dur = try col(a, "dur", .duration, null, &stamps);
    try cols.append(a, dur[0]);
    try data.append(a, dur[1]);
    const fl = [_]f64{ std.math.floatMax(f64), -std.math.floatMax(f64), 5e-324, 1e22, std.math.nan(f64), std.math.inf(f64), -0.0, 0.5, 1e-7, 123456789.125 };
    try cols.append(a, .{ .name = "f", .type = .float });
    try data.append(a, .{ .float = .{ .values = try a.dupe(f64, &fl), .valid = null } });
    return .{ .columns = cols.items, .data = data.items, .len = stamps.len };
}

fn nestedFrame(a: std.mem.Allocator, depth: usize) !Frame {
    var json: std.ArrayList(u8) = .empty;
    try json.appendSlice(a, "[{\"l\":");
    for (0..depth) |_| try json.appendSlice(a, "[1,");
    try json.appendSlice(a, "\"x\"");
    for (0..depth) |_| try json.append(a, ']');
    try json.appendSlice(a, ",\"s\":");
    for (0..depth) |_| try json.appendSlice(a, "{\"k\":");
    try json.appendSlice(a, "null");
    for (0..depth) |_| try json.append(a, '}');
    try json.appendSlice(a, ",\"ts\":[\"2020-01-01T00:00:00Z\"]}]");
    return df.readJson(a, json.items, .{ .parse_dates = true });
}

fn writeEverything(a: std.mem.Allocator, f: Frame) !void {
    var aw: std.Io.Writer.Allocating = .init(a);
    const layouts = [_]?[]const u8{ null, "%Y-%m-%d %H:%M:%S%z", "%F %T %:z", "%Z %a %b %d %j %V %G %u %p %I %y %f", "%-d" };
    inline for (.{ df.CsvQuote.necessary, df.CsvQuote.always, df.CsvQuote.never, df.CsvQuote.non_numeric }) |q| {
        for (layouts) |l| {
            aw.clearRetainingCapacity();
            df.writeCsv(a, &aw.writer, f, .{ .quote_style = q, .datetime_format = l, .date_format = l, .float_scientific = true, .float_precision = 22, .decimal = ',' }) catch {};
            aw.clearRetainingCapacity();
            df.writeCsv(a, &aw.writer, f, .{ .quote_style = q, .datetime_format = l, .float_scientific = false, .float_precision = 0, .include_bom = true, .line_terminator = .crlf }) catch {};
        }
    }
    const orients = [_]df.JsonOrient{ .records, .columns, .split, .index, .values, .table };
    for (orients) |o| {
        for ([_]df.JsonDateFormat{ .iso, .epoch }) |dfm| {
            for ([_]df.JsonDateUnit{ .s, .ms, .us, .ns }) |u| {
                for ([_]?u8{ null, 0, 1, 255 }) |ind| {
                    for ([_]?u8{ null, 0, 15, 255 }) |dp| {
                        aw.clearRetainingCapacity();
                        df.writeJsonOpts(a, &aw.writer, f, o, .{ .date_format = dfm, .date_unit = u, .indent = ind, .double_precision = dp, .force_ascii = ind == 1, .max_indent_bytes = 1 << 16 }) catch {};
                    }
                }
            }
        }
    }
    _ = try df.format(a, f, .{ .show_dtypes = true, .show_shape = true });
    _ = try df.toMarkdown(a, f, .{});
    _ = try df.glimpse(a, f, .{ .max_width = 40 });
    _ = try df.glimpse(a, f, .{});
    for ([_]?u8{ null, 0, 22, 255 }) |p| {
        _ = try df.toHtml(a, f, .{ .float_precision = p });
        _ = try df.toHtml(a, f, .{ .float_precision = p, .escape = false, .max_cell_chars = 3 });
    }
}

test "the writers over zoned, duration and nested cells never trap (sweep B clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try writeEverything(a, try zonedFrame(a));
    try writeEverything(a, try nestedFrame(a, 3));
    try writeEverything(a, try nestedFrame(a, 70));
}

// ── clean probes: the readers over hostile documents under every option ───────────────

const docs = [_][]const u8{
    "",
    "[]",
    "{}",
    "[{}]",
    "[{\"a\":1},{\"a\":\"x\"},{\"a\":[1,{\"b\":null}]},{\"a\":{\"b\":[]}}]",
    "[{\"a\":1,\"a\":2}]",
    "[{\"a\":{\"x\":1,\"x\":2},\"a\":3}]",
    "{\"a\":[1,2],\"a\":[3],\"b\":[null,\"2020-01-01\"]}",
    "{\"a\":[1,2],\"b\":[3]}",
    "{\"columns\":[\"a\",\"b\"],\"index\":[0],\"data\":[[1,2],[3]]}",
    "{\"columns\":[\"a\",\"a\"],\"data\":[]}",
    "{\"columns\":[\"a\"],\"data\":[[1,2]]}",
    "{\"0\":{\"a\":1},\"1\":{\"b\":2}}",
    "[[1,\"x\"],[2],[3,null,4.5]]",
    "{\"schema\":{\"fields\":[1],\"primaryKey\":[\"a\",\"a\",\"zz\"]},\"data\":[{\"a\":1}]}",
    "{\"schema\":{\"fields\":[{\"name\":\"a\",\"tz\":\"Europe/Prague\"},{\"name\":\"b\",\"tz\":\"No/Such\"},{\"tz\":3}],\"primaryKey\":[\"index\"]},\"data\":[{\"index\":0,\"a\":\"2020-01-01T00:00:00Z\",\"b\":1}]}",
    "{\"schema\":{\"fields\":[{\"name\":\"a\",\"tz\":\"Europe/Prague\"}],\"primaryKey\":[\"a\"]},\"data\":[{\"a\":\"2020-01-01T00:00:00Z\"}],\"data\":[]}",
    "[{\"a\":9223372036854775808,\"b\":-9223372036854775808,\"c\":1e999,\"d\":\"2020-02-30\",\"e\":\"0000-01-01T00:00:00+23:59\"}]",
    "[{\"a\":9223372036854775807,\"b\":-9223372036854775808}]",
    "[{\"a\":\"\\ud800\"}]",
    "[{\"a\":\"\\u0000\\ud83d\\ude00\"}]",
    "[{\"a\":1}",
    "[{\"a\":1}]]",
    "[{\"a\":1},]",
    "{\"a\":[1,2,}",
    "\xef\xbb\xbf[{\"a\":1}]",
    "[{\"a\":\"\xff\"}]",
};

test "the JSON readers over hostile documents under every option never trap (sweep B clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const orients = [_]df.JsonReadOrient{ .records, .columns, .split, .index, .values, .table };
    const type_sets = [_][]const df.TypeOverride{
        &.{},
        &.{.{ .name = "a", .type = .list }},
        &.{.{ .name = "a", .type = .@"struct" }},
        &.{.{ .name = "a", .type = .timestamp, .time_zone = "Europe/Prague" }},
        &.{.{ .name = "a", .type = .duration }},
        &.{.{ .name = "a", .type = .decimal }},
        &.{.{ .name = "a", .type = .categorical }},
        &.{.{ .name = "a", .type = .int }},
        &.{.{ .name = "a", .type = .text }},
        &.{.{ .name = "zz", .type = .int }},
        &.{.{ .name = "a", .type = .timestamp, .time_zone = "No/Such" }},
        &.{.{ .name = "a", .type = .int, .time_zone = "UTC" }},
    };
    for (docs) |doc| {
        for (orients) |o| {
            for (type_sets) |ts| {
                for ([_]bool{ false, true }) |pd| {
                    for ([_]?usize{ null, 0, 1 }) |nr| {
                        _ = df.readJson(a, doc, .{ .orient = o, .types = ts, .parse_dates = pd, .n_rows = nr }) catch {};
                        _ = df.readJson(a, doc, .{ .orient = o, .types = ts, .duplicate_keys = .last, .epoch_dates = &.{"a"}, .date_unit = .ns }) catch {};
                        _ = df.readJson(a, doc, .{ .orient = o, .types = ts, .epoch_durations = &.{ "a", "b" }, .date_unit = .s }) catch {};
                    }
                }
            }
            _ = df.readJson(a, doc, .{ .orient = o, .columns = &.{"a"}, .max_columns = 1, .max_cells = 3, .max_cell_bytes = 2, .max_rows = 1 }) catch {};
            _ = df.readJson(a, doc, .{ .orient = o, .columns = &.{ "a", "a" }, .enums = &.{.{ .name = "a", .categories = &.{ "x", "y" } }} }) catch {};
        }
        _ = df.readNdjson(a, doc, .{ .duplicate_keys = .last, .max_bytes = 8 }) catch {};
        _ = df.readNdjson(a, doc, .{ .parse_dates = true, .n_rows = 1, .epoch_dates = &.{"a"} }) catch {};
    }
}

test "deeply nested JSON reads, keeps its text past the depth bound and writes back (sweep B clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]usize{ 63, 64, 65, 200, 5000 }) |depth| {
        var json: std.ArrayList(u8) = .empty;
        try json.appendSlice(a, "[");
        for (0..depth) |_| try json.appendSlice(a, "{\"k\":[");
        try json.appendSlice(a, "1");
        for (0..depth) |_| try json.appendSlice(a, "]}");
        try json.appendSlice(a, ",{\"k\":2,\"k\":3}]");
        for ([_]df.JsonDuplicateKeys{ .reject, .last }) |dk| {
            const f = df.readJson(a, json.items, .{ .duplicate_keys = dk }) catch continue;
            var aw: std.Io.Writer.Allocating = .init(a);
            try df.writeJson(&aw.writer, f, .records);
            try df.writeCsv(a, &aw.writer, f, .{});
        }
    }
}

test "CsvChunkReader over hostile streams under every option never traps (sweep B clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inputs = [_][]const u8{
        "",
        "a",
        "a,b\n",
        "a,b\n1,2",
        "a,b\r\n1,2\r\n3,x\r\n",
        "\xef\xbb\xbfa,b\n1,2\n",
        "a,b\n\"1,2\n3,4\n",
        "a,b\n1,\"2\n\n\n",
        "a,b\n1,2,3\n4,5\n",
        "#c\na,b\n#d\n1,2\n\n\n3,4\n",
        "a\n\"\"\n\"\r\"\n\"x\"\"y\"\n",
        "a,b\n\"\xff\",\"\x00\"\n",
        "x;y\n1,5;2\n1.000,5;3\n",
    };
    const sets = [_]df.CsvReadOptions{
        .{},
        .{ .has_header = false },
        .{ .has_header = false, .names = &.{ "p", "q" } },
        .{ .quote = 0 },
        .{ .strict_quotes = false },
        .{ .strict_quotes = false, .max_quoted_lines = 1 },
        .{ .comment = '#', .skip_rows = 1, .skip_rows_after_header = 1 },
        .{ .on_bad_lines = .skip, .bad_lines_skipped = null },
        .{ .truncate_ragged = true },
        .{ .escape_char = '\\', .double_quote = false },
        .{ .delimiter = ';', .thousands = '.', .decimal = ',' },
        .{ .types = &.{.{ .name = "a", .type = .int }}, .null_values = &.{"x"} },
        .{ .types = &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .float } }, .extra_null_values = &.{"x"}, .row_index_name = "ix", .row_index_offset = std.math.maxInt(i64) },
        .{ .parse_dates = true, .date_format = "%Y-%m-%d" },
        .{ .max_bytes = 3, .max_record_bytes = 2 },
        .{ .max_rows = 1, .max_columns = 1, .max_cell_bytes = 1, .max_cells = 2 },
        .{ .row_index_name = "a" },
        .{ .columns = &.{"b"}, .enums = &.{.{ .name = "b", .categories = &.{"2"} }} },
    };
    const copt_sets = [_]cc.ChunkOptions{ .{}, .{ .schema = .per_chunk }, .{ .infer_rows = 1 }, .{ .infer_rows = 1 << 40 }, .{ .ignore_errors = true } };
    for (inputs) |bytes| {
        for (sets) |o| {
            for (copt_sets) |co| {
                for ([_]usize{ 1, 2, 1 << 40 }) |n| {
                    for ([_]usize{ 1, 3, 0 }) |step| {
                        var slow: Slow = undefined;
                        slow.init(bytes, step);
                        var rd = cc.CsvChunkReader.init(testing.allocator, &slow.interface, o, co) catch continue;
                        defer rd.deinit();
                        var k: usize = 0;
                        while (k < 8) : (k += 1) {
                            const got = rd.next(a, n) catch break;
                            if (got == null) break;
                        }
                    }
                }
            }
        }
    }
}

test "readCsv with every new option over hostile text never traps (sweep B clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const texts = [_][]const u8{
        "a,b,c\n1,2020-01-01,1:02:03\n2,31/12/2020,P1DT2H\n,,\n9223372036854775807,-,PT9223372036854.775808S\n",
        "a\n1.5\n1,5\n1e5\n+.5\n-\n.\n0x10\ninf\nNaN\n 7 \n",
        "a,b\n\"1,000\",\"1.000,5\"\n\"1,2\",3\n",
        "d\n2020-01-01T00:00:00+14:00\n2020-01-01 00:00:00Z\n0000-01-01\n9999-12-31T23:59:60Z\n",
        "d\n-P1D\nP1W\nPT0.0000001S\n1 days 00:00:01\n-1 days +23:58:30\n99999999999999 days 00:00:00\n",
        "a,a,a.1,,\n1,2,3,4,5\n",
    };
    const fmts = [_]?[]const u8{ null, "%Y-%m-%d", "%d/%m/%Y %H:%M", "%Y%", "%-d", "[", "%%", "%z %Z %p" };
    for (texts) |t| {
        for (fmts) |fm| {
            for ([_]u8{ 0, ',', '.', ' ' }) |th| {
                for ([_]u8{ '.', ',', 0, ';' }) |dc| {
                    for ([_]df.ColumnType{ .int, .float, .decimal, .bool, .date, .timestamp, .duration, .categorical, .text, .list }) |ty| {
                        const ov = [_]df.TypeOverride{.{ .name = "a", .type = ty, .time_zone = if (ty == .timestamp) "Europe/Prague" else null }};
                        _ = df.readCsv(a, t, .{ .date_format = fm, .thousands = th, .decimal = dc, .parse_dates = true, .types = &ov, .true_values = &.{"1"}, .false_values = &.{"2"} }) catch {};
                        _ = df.readCsv(a, t, .{ .date_format = fm, .thousands = th, .decimal = dc, .types = &ov, .column_null_values = &.{.{ .name = "a", .values = &.{"1"} }}, .skipfooter = 1, .na_filter = false }) catch {};
                    }
                }
            }
        }
    }
}

// ── clean probes: dtfn over extreme instants, steps and zones ─────────────────────────

fn extremeInstants() [12]i64 {
    const imin = std.math.minInt(i64);
    const imax = std.math.maxInt(i64);
    return .{ imin, imin + 1, -86_400_000_000, -1, 0, 1, 86_400_000_000, 4 * 86_400_000_000, 1_700_000_000_000_000, imax - 86_400_000_000, imax - 1, imax };
}

test "dtfn rounding, steps and zone conversions over extreme instants never trap (sweep B clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const imax = std.math.maxInt(i64);
    const durs = [_]dtf.Duration{
        .{ .us = 1 },
        .{ .us = 86_400_000_000 },
        .{ .us = 7 * 86_400_000_000, .weeks = 1 },
        .{ .us = 14 * 86_400_000_000, .weeks = 2 },
        .{ .us = imax },
        .{ .months = 1 },
        .{ .months = 12 },
        .{ .months = imax },
        .{ .months = 5, .us = 5 },
        .{},
        .{ .us = -1 },
        .{ .months = -1 },
    };
    const zones = [_]*const tz.Zone{ tz.find("Europe/Prague").?, tz.find("Pacific/Kiritimati").?, tz.find("America/St_Johns").?, tz.find("UTC").? };
    for (extremeInstants()) |us| {
        for (durs) |d| {
            for ([_]dtf.RoundTo{ .floor, .ceil, .nearest }) |m| {
                _ = try dtf.roundTo(a, .{ .int = us }, d, m);
                for (zones) |z| _ = try dtf.roundToZoned(a, .{ .int = us }, d, m, z);
            }
            for ([_]i64{ 0, 1, -1, 7, std.math.minInt(i64), imax, 1 << 40 }) |k| {
                _ = dtf.stepInstant(us, d, k);
                _ = dtf.scaleDuration(d, k);
            }
        }
        for (zones) |z| {
            for ([_]dtf.TzPolicy{ .compatible, .earlier, .later, .null }) |p| _ = try dtf.fromLocal(a, .{ .int = us }, z, p);
            _ = try dtf.toLocal(a, .{ .int = us }, z);
            _ = dtf.zoneOffset(.{ .int = us }, z, .total);
            _ = dtf.zoneOffset(.{ .int = us }, z, .base);
            _ = dtf.zoneOffset(.{ .int = us }, z, .dst);
            _ = try dtf.strftimeZoned(a, .{ .int = us }, "%Y-%m-%d %H:%M:%S %Z %z %j %a", null, z);
        }
        _ = dtf.components(us);
        _ = dtf.replaceParts(a, .{ .int = us }, .{ imax, 0, 31, 24, 60, 60, 1_000_000 }) catch {};
        _ = try dtf.replaceParts(a, .{ .int = us }, .{ 2020, 2, 30, null, null, null, null });
        _ = dtf.combine(.{ .int = us }, .{ .int = us });
        _ = try dtf.addBusinessDaysMask(a, .{ .int = us }, 5, dtf.monday_to_friday, &.{}, .forward);
        _ = try dtf.part(a, .{ .int = us }, .total_seconds_f64);
        _ = try dtf.part(a, .{ .int = us }, .td_nanoseconds);
        _ = try dtf.fromEpoch(a, .{ .int = us }, .day);
        _ = try dtf.fromEpoch(a, .{ .int = us }, .ns);
    }
    for ([_]i64{ std.math.minInt(i64), -1, 0, 1, 5, 1 << 30, (1 << 30) + 1, imax }) |n| {
        const hol = [_]i64{ -3, 0, 4, 5, 6, 1000 };
        for ([_][7]bool{ dtf.monday_to_friday, .{ false, false, false, false, false, false, false }, .{ true, true, true, true, true, true, true }, .{ false, false, false, false, false, true, false } }) |mask| {
            for ([_]dtf.Roll{ .forward, .backward }) |r| {
                for ([_]i64{ std.math.minInt(i64), -5, 0, 19000, 1 << 30, imax }) |day| {
                    _ = dtf.addBizDaysGeneral(day, n, mask, &hol, r);
                    _ = dtf.addBizDaysGeneral(day, n, mask, &.{}, r);
                }
            }
        }
    }
    _ = dtf.makeDate(a, std.math.minInt(i64), 13, 0) catch {};
    _ = try dtf.makeDate(a, 2020, 2, 30);
    _ = try dtf.makeDate(a, std.math.maxInt(i32), 12, 31);
    _ = dtf.makeDatetime(std.math.maxInt(i32), 12, 31, 23, 59, 59, 999_999);
    _ = dtf.makeDatetime(std.math.minInt(i32), 1, 1, 0, 0, 0, 0);
    _ = dtf.makeDuration(.{ imax, imax, imax, imax, imax, imax, imax });
    for ([_][]const u8{ "", "%", "%-", "%-d", "%:", "%:z", "[", "]", "][", "%Y%", "%%%", "\x00", "%Q", "%-%-d" }) |fmt| {
        _ = dtf.translateFormat(a, fmt) catch {};
        _ = dtf.translateInfer(a, fmt) catch {};
    }
    for ([_][]const u8{ "", "1", "-", "9999-99-99", "2020-02-30 25:61", "\xff\xfe", "12:34:56.1234567", "12:3", "-1:30" }) |s| {
        for (dtf.inferFormats(false)) |l| _ = try dtf.strptime(a, .{ .text = s }, l, .timestamp);
        _ = try dtf.parseMixed(a, .{ .text = s }, .date, dtf.inferFormats(true));
        _ = dtf.combine(.{ .text = "2020-01-01" }, .{ .text = s });
    }
}

// ── clean probes: the verbs over extreme frames under every new option ────────────────

fn verbFrame(a: std.mem.Allocator, zone: ?[]const u8) !Frame {
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);
    const imin = std.math.minInt(i64);
    const imax = std.math.maxInt(i64);
    const stamps = [_]i64{ imin, imin + 1, -1, 0, 1, 86_400_000_000, 1_700_000_000_000_000, imax - 86_400_000_000, imax - 1, imax };
    const xs = [_]f64{ nan, inf, -inf, std.math.floatMax(f64), -std.math.floatMax(f64), 5e-324, -0.0, 0.5, -2.5, 1e19 };
    const ks = [_]i64{ imin, -1, 0, 1, 1, 2, 2, 3, imax - 1, imax };
    const gs = [_][]const u8{ "a", "b", "a", "", "b", "a", "c", "c", "a", "b" };
    const cols = try a.dupe(Column, &.{
        .{ .name = "g", .type = .text },
        .{ .name = "k", .type = .int },
        .{ .name = "x", .type = .float },
        .{ .name = "t", .type = .timestamp, .time_zone = zone },
        .{ .name = "d", .type = .duration },
    });
    const offs = try a.alloc(usize, gs.len + 1);
    var bytes: std.ArrayList(u8) = .empty;
    for (gs, 0..) |s, i| {
        offs[i] = bytes.items.len;
        try bytes.appendSlice(a, s);
    }
    offs[gs.len] = bytes.items.len;
    const valid = try a.dupe(u64, &.{0b1111111011});
    const data = try a.dupe(df.ColumnData, &.{
        .{ .text = .{ .offsets = offs, .bytes = bytes.items, .valid = null } },
        .{ .int = .{ .values = try a.dupe(i64, &ks), .valid = valid } },
        .{ .float = .{ .values = try a.dupe(f64, &xs), .valid = valid } },
        .{ .int = .{ .values = try a.dupe(i64, &stamps), .valid = null } },
        .{ .int = .{ .values = try a.dupe(i64, &stamps), .valid = valid } },
    });
    return .{ .columns = cols, .data = data, .len = gs.len };
}

test "groupByDynamic over extreme instants under every option never traps (sweep B clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var loop = std.heap.ArenaAllocator.init(testing.allocator);
    defer loop.deinit();
    const f0 = try verbFrame(arena.allocator(), null);
    const f1 = try verbFrame(arena.allocator(), "Europe/Prague");
    const aggs = [_]df.AggCol{
        .{ .src = "x", .out = "s", .func = .sum },
        .{ .src = "t", .out = "tmin", .func = .min },
        .{ .src = "t", .out = "tfirst", .func = .first },
        .{ .src = "k", .out = "n", .func = .count },
        .{ .src = "d", .out = "dm", .func = .mean },
    };
    const rules = [_][]const u8{ "D", "h", "min", "s", "ms", "us", "MS", "QS", "YS", "ME", "QE", "YE", "W", "W-MON", "2D", "1M", "0D", "99999999999999999999D", "x", "" };
    const closed = [_]df.DynamicClosed{ .left, .right, .both, .none };
    const labels = [_]df.DynamicLabel{ .left, .right, .datapoint };
    const starts = [_]df.StartBy{ .window, .datapoint, .monday, .sunday };
    const origins = [_]?df.Origin{ null, .epoch, .start, .start_day, .end, .end_day };
    for ([_]Frame{ f0, f1 }) |f| {
        for (rules) |r| for (closed) |c| for (labels) |l| for (starts) |sb| for (origins) |o| {
            _ = loop.reset(.retain_capacity);
            _ = df.groupByDynamic(loop.allocator(), f, .{ .index = "t", .rule = r, .closed = c, .label = l, .start_by = sb, .origin = o, .include_boundaries = true, .by = &.{"g"}, .aggs = &aggs }) catch {};
        };
        for ([_][]const u8{ "1us", "1h", "1d", "1w", "1mo", "1y", "7d", "-1d", "0s", "1ns", "9223372036854775807us" }) |every| {
            for ([_]?[]const u8{ null, "1y", "1us", "0s", "-1d" }) |period| for ([_]?[]const u8{ null, "-1d", "1y", "1ns" }) |offset| {
                _ = loop.reset(.retain_capacity);
                _ = df.groupByDynamic(loop.allocator(), f, .{ .index = "t", .every = every, .period = period, .offset = offset, .aggs = &aggs, .closed = .both }) catch {};
                _ = df.groupByDynamic(loop.allocator(), f, .{ .index = "t", .every = every, .aggs = &aggs }) catch {};
            };
            _ = df.upsample(loop.allocator(), f, .{ .time = "t", .every = every }) catch {};
        }
        for ([_]df.InterpolateSpec{
            .{ .col = "x" },
            .{ .col = "x", .by = "t", .method = .slinear },
            .{ .col = "x", .by = "k", .method = .zero, .limit = 1, .limit_direction = .both, .limit_area = .inside },
            .{ .col = "x", .method = .nearest, .limit = 0, .limit_direction = .backward, .limit_area = .outside, .out = "y" },
            .{ .col = "k", .by = "d", .limit = std.math.maxInt(usize) },
        }) |s| {
            _ = loop.reset(.retain_capacity);
            _ = df.interpolate(loop.allocator(), f, s) catch {};
        }
    }
}

test "describe, quantiles, cut and the value verbs over extreme columns never trap (sweep B clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);
    for ([_]?[]const u8{ null, "Asia/Kolkata" }) |zone| {
        const f = try verbFrame(a, zone);
        for ([_]df.DescribeSpec{
            .{},
            .{ .all = true },
            .{ .percentiles = &.{ 0, 1, 1, 0.5 } },
            .{ .percentiles = &.{nan} },
            .{ .percentiles = &.{ -0.1, 1.1 } },
            .{ .include = &.{ .timestamp, .duration }, .percentiles = &.{ 1e-300, 0.9999999999999999 } },
            .{ .exclude = &.{.text}, .cols = &.{ "t", "d", "x" } },
            .{ .cols = &.{"nope"} },
        }) |s| _ = df.describeWith(a, f, s) catch {};
        for ([_][]const f64{ &.{}, &.{ 0, 0.5, 1 }, &.{nan}, &.{inf}, &.{ -0.0, 1e-300 } }) |qs| {
            for ([_]df.Interpolation{ .linear, .lower, .higher, .midpoint, .nearest, .equiprobable }) |ip| _ = df.quantiles(a, f, .{ .qs = qs, .interpolation = ip, .cols = &.{ "x", "k", "t" } }) catch {};
        }
        for ([_][]const f64{ &.{}, &.{ 0, 1 }, &.{ nan, 1 }, &.{ -inf, inf }, &.{ 1e300, 1e301 }, &.{ 0, 0 }, &.{ 1, 0 } }) |edges| {
            for ([_]bool{ false, true }) |right| for ([_]u8{ 0, 3, 20, 255 }) |p| {
                _ = df.cut(a, f, .{ .col = "x", .out = "bin", .edges = edges, .right = right, .include_lowest = right, .interval_labels = true, .precision = p, .break_out = "br" }) catch {};
            };
        }
        for ([_]usize{ 0, 1, 3, 4096, 1 << 20, (1 << 20) + 1, std.math.maxInt(usize) }) |bins| {
            _ = df.cut(a, f, .{ .col = "x", .out = "bin", .bins = bins, .interval_labels = true }) catch {};
            _ = df.cut(a, f, .{ .col = "k", .out = "bin", .bins = bins }) catch {};
            _ = df.qcut(a, f, .{ .col = "x", .out = "q", .bins = bins, .duplicates = .drop, .interval_labels = true, .precision = 255 }) catch {};
            _ = df.qcut(a, f, .{ .col = "t", .out = "q", .bins = bins }) catch {};
        }
        _ = df.qcut(a, f, .{ .col = "x", .out = "q", .probs = &.{ 0, 0.5, 1 }, .break_out = "b" }) catch {};
        _ = df.qcut(a, f, .{ .col = "x", .out = "q", .probs = &.{ nan, 2 } }) catch {};
        for ([_]bool{ false, true }) |nm| for ([_]bool{ false, true }) |so| for ([_]bool{ false, true }) |asc| for ([_]bool{ false, true }) |km| {
            _ = df.valueCounts(a, f, .{ .cols = &.{"g"}, .normalize = nm, .sort = so, .ascending = asc, .keep_missing = km }) catch {};
            _ = df.valueCounts(a, f, .{ .cols = &.{ "g", "k", "x" }, .normalize = nm, .sort = so, .ascending = asc, .keep_missing = km }) catch {};
        };
        _ = df.ohlc(a, f, .{ .group_by = &.{"g"}, .value_col = "x", .prefix = "p" }) catch {};
        for ([_]?usize{ null, 0, 1, std.math.maxInt(usize) }) |lim| {
            _ = df.fillna(a, f, .{ .value = .{ .int = 7 }, .limit = lim }) catch {};
            _ = df.fillna(a, f, .{ .per_column = &.{ .{ .col = "x", .value = .{ .float = 1 } }, .{ .col = "g", .value = .{ .text = "z" } } }, .limit = lim }) catch {};
            for ([_]bool{ false, true }) |ac| for ([_]df.FillStrategy{ .forward, .backward, .mean, .min, .max, .zero, .one }) |st| {
                _ = df.fillNull(a, f, .{ .strategy = st, .limit = lim, .across_columns = ac, .subset = &.{ "k", "x", "d" } }) catch {};
            };
        }
    }
}

test "aggregate, pivot, join, concat and the structure verbs over extreme frames never trap (sweep B clean probe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f0 = try verbFrame(a, null);
    const f1 = try verbFrame(a, "Europe/Prague");
    const empty: Frame = .{ .columns = f0.columns, .data = &.{}, .len = 0 };
    const cat = try df.readCsv(a, "c,k\nx,1\ny,\nx,2\n,3\n", .{ .types = &.{.{ .name = "c", .type = .categorical }}, .enums = &.{.{ .name = "c", .categories = &.{ "y", "x" } }} });
    const funcs = [_]df.AggFn{ .sum, .mean, .count, .min, .max, .first, .last, .std, .@"var", .median, .quantile, .nunique, .sum_exact, .size, .prod, .any, .all, .sem, .skew, .kurt, .mode, .arg_min, .arg_max, .implode };
    for ([_]Frame{ f0, f1, empty, cat }) |f| {
        for (f.columns) |c| {
            for (funcs) |fn_| {
                for ([_]bool{ false, true }) |tr| for ([_]df.Interpolation{ .linear, .equiprobable, .nearest }) |ip| {
                    _ = df.aggregate(a, f, .{ .group_by = &.{if (f.columns.len > 2) "g" else "k"}, .aggs = &.{.{ .src = c.name, .out = "o", .func = fn_, .q = 0.3, .interpolation = ip }}, .temporal_results = tr, .sort_groups = tr }) catch {};
                };
                _ = df.aggregate(a, f, .{ .group_by = &.{}, .aggs = &.{.{ .src = c.name, .out = "o", .func = fn_, .q = std.math.nan(f64), .min_count = 5 }}, .skip_na = true }) catch {};
            }
        }
    }
    for ([_]Frame{ f0, f1, empty }) |f| {
        for ([_]bool{ false, true }) |m| for ([_]bool{ false, true }) |sc| for ([_]Value{ .null, .{ .text = "t" }, .{ .bool = true }, .{ .float = 1 } }) |fl| {
            _ = df.pivot(a, f, .{ .row_key = "g", .col_key = "k", .value_col = "x", .margins = m, .sort_columns = sc, .fill = fl, .agg = .sum }) catch {};
            _ = df.pivot(a, f, .{ .row_key = "k", .col_key = "g", .value_col = "t", .margins = m, .sort_columns = sc, .fill_value = 2.5, .agg = .first }) catch {};
            _ = df.pivotMany(a, f, .{ .row_key = "g", .col_key = "k", .values = &.{ "x", "t", "d" }, .aggs = &.{ .mean, .max }, .margins = m, .sort_columns = sc, .fill = fl }) catch {};
        };
        const hows = [_]df.JoinSpec{
            .{ .on = "k", .how = .inner },
            .{ .on = "k", .how = .left, .indicator = "ind", .sort = true },
            .{ .on = "k", .how = .right, .coalesce_keys = true, .left_suffix = "_l", .keep_right_keys = true },
            .{ .on = "k", .how = .full, .indicator = "ind", .sort = true, .null_keys = .no_match },
            .{ .on = "k", .how = .semi, .validate = .one_to_one },
            .{ .on = "k", .how = .anti, .validate = .many_to_one },
            .{ .how = .cross, .suffix = "_r" },
            .{ .keys = &.{ "g", "k" }, .how = .full, .validate = .one_to_many, .suffix = "_r", .left_suffix = "_l" },
            .{ .how = .inner },
            .{ .on = "nope", .how = .inner },
        };
        for (hows) |j| for ([_]Frame{ f0, f1, empty, cat }) |r| {
            _ = df.join(a, f, r, j) catch {};
        };
        _ = df.transpose(a, f, .{ .header_name = "h", .names_from = "g" }) catch {};
        _ = df.transpose(a, f, .{ .names = &.{ "a", "a" } }) catch {};
        _ = df.sort(a, f, .{ .key = "x", .then_by = &.{ .{ .key = "t", .dir = .desc, .missing = .first }, .{ .key = "g", .missing = .last } }, .missing = .first }) catch {};
        _ = df.columnBytes(f, 0);
        for ([_]df.Selector{
            .all,
            .{ .matches = "(" },
            .{ .matches = "^(?i)[a-z]$" },
            .{ .matches = "(a+)+$" },
            .{ .any_of = &.{ .alpha, .digit, .alphanumeric, .nested, .first, .last } },
            .{ .by_index = &.{99} },
        }) |s| _ = df.selectColumns(a, f, s) catch {};
    }
    for ([_][]const Frame{ &.{ f0, f1 }, &.{ f1, f0 }, &.{ f0, empty }, &.{ f0, cat }, &.{}, &.{ f0, f0, f0 } }) |fs| {
        for ([_]df.ConcatHow{ .vertical, .horizontal, .diagonal }) |how| _ = df.concat(a, fs, how) catch {};
    }
    const schema = [_]Column{ .{ .name = "t", .type = .timestamp, .time_zone = "Asia/Tokyo" }, .{ .name = "x", .type = .int }, .{ .name = "zz", .type = .text } };
    const bad = [_]Column{.{ .name = "t", .type = .timestamp, .time_zone = "No/Such" }};
    for ([_]Frame{ f0, f1 }) |f| {
        for ([_]bool{ false, true }) |c| {
            _ = df.matchToSchema(a, f, &schema, .{ .cast = c, .missing_columns = .insert, .extra_columns = .ignore }) catch {};
            _ = df.matchToSchema(a, f, &bad, .{ .cast = c }) catch {};
        }
    }
}
