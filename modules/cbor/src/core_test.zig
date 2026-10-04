// SPDX-License-Identifier: MIT
//! Tests for the 2026-10-04 additions: strict decoding, preferred float
//! serialization, CBOR Sequences, diagnostic notation, the streaming
//! reader/writer and the typed mapping.
//!
//! Expected values come from outside this module: the RFC 8949 Appendix A
//! table (`diag_vectors.zig`, transcribed from the RFC text by
//! `tools/gen_diag_vectors.py`), Python cbor2 driven as a black box
//! (`cbor2_vectors.zig`, `tools/gen_cbor2_vectors.py`), or bytes derived by
//! hand from the RFC rules — each such case says how.

const std = @import("std");
const testing = std.testing;
const cbor = @import("root.zig");
const Value = cbor.Value;
const MapEntry = cbor.MapEntry;
const diag_vectors = @import("diag_vectors.zig");
const cbor2 = @import("cbor2_vectors.zig");

fn unhex(comptime h: []const u8) [h.len / 2]u8 {
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

fn unhexAlloc(a: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

fn expectDiag(a: std.mem.Allocator, hex: []const u8, want: []const u8) !void {
    const bytes = try unhexAlloc(a, hex);
    defer a.free(bytes);
    const v = try cbor.decode(a, bytes, .{});
    defer cbor.freeValue(a, v);
    const got = try cbor.diagnostic(a, v);
    defer a.free(got);
    testing.expectEqualStrings(want, got) catch |e| {
        std.debug.print("hex {s}\n", .{hex});
        return e;
    };
}

// ── diagnostic notation: RFC 8949 Appendix A ───────────────────────────────

test "diag: every RFC 8949 Appendix A row prints as the RFC prints it" {
    const a = testing.allocator;
    var exact: usize = 0;
    for (diag_vectors.rows) |row| switch (row.kind) {
        .exact => {
            try expectDiag(a, row.hex, row.diag);
            exact += 1;
        },
        // The RFC shows a bignum's numeric value; this module prints the
        // generic tag form over the byte string, read off the hex by hand
        // (c2 = tag 2, 49 = byte string of 9, then the 9 bytes).
        .bignum => try expectDiag(a, row.hex, if (row.hex[1] == '2')
            "2(h'010000000000000000')"
        else
            "3(h'010000000000000000')"),
        // A decoded Value keeps no encoding indicator: the indefinite item
        // prints as its definite twin — the RFC's text without "_ ".
        .indefinite => {
            if (std.mem.startsWith(u8, row.diag, "(_ h'")) {
                try expectDiag(a, row.hex, "h'0102030405'");
            } else if (std.mem.startsWith(u8, row.diag, "(_ \"")) {
                try expectDiag(a, row.hex, "\"streaming\"");
            } else {
                var buf: [256]u8 = undefined;
                const n = std.mem.replacementSize(u8, row.diag, "_ ", "");
                _ = std.mem.replace(u8, row.diag, "_ ", "", &buf);
                try expectDiag(a, row.hex, buf[0..n]);
            }
        },
    };
    // 81 data rows in the RFC table; all but 2 bignums and 11 indefinite
    // ones are compared verbatim.
    try testing.expectEqual(@as(usize, 81), diag_vectors.rows.len);
    try testing.expectEqual(@as(usize, 81 - 2 - 11), exact);
}

test "diag: escapes, invalid UTF-8 in a hand-built text, nesting" {
    const a = testing.allocator;
    // JSON escapes for controls; DEL and other C0 controls as \u00XX.
    const t: Value = .{ .text = "a\n\t\x01\x7f\"" };
    const got = try cbor.diagnostic(a, t);
    defer a.free(got);
    try testing.expectEqualStrings("\"a\\n\\t\\u0001\\u007f\\\"\"", got);
    // A hand-built text with a lone continuation byte and a truncated
    // sequence: each bad byte is U+FFFD, the rest is kept.
    const bad: Value = .{ .text = "x\x80y\xe6\xb0" };
    const got2 = try cbor.diagnostic(a, bad);
    defer a.free(got2);
    try testing.expectEqualStrings("\"x\\ufffdy\\ufffd\\ufffd\"", got2);
    // Writer onto a too-small fixed buffer fails, it does not overrun.
    var small: [4]u8 = undefined;
    var w: std.Io.Writer = .fixed(&small);
    try testing.expectError(error.WriteFailed, cbor.writeDiagnostic(&w, .{ .text = "abcdef" }));
}

// ── preferred float serialization (cbor2 oracle) ───────────────────────────

test "floats: shortest exact width matches cbor2's canonical output" {
    const a = testing.allocator;
    for (cbor2.floats) |f| {
        const x: f64 = @bitCast(f.bits);
        const want = try unhexAlloc(a, f.canonical_hex);
        defer a.free(want);
        for ([_]cbor.EncodeOptions{ .{ .shortest_floats = true }, .{ .canonical = true } }) |opts| {
            const got = try cbor.encode(a, .{ .f64 = x }, opts);
            defer a.free(got);
            testing.expectEqualSlices(u8, want, got) catch |e| {
                std.debug.print("float bits {x}\n", .{f.bits});
                return e;
            };
        }
        // The streaming writer's `float` is the same function.
        var buf: [9]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try cbor.Writer.init(&w).float(x);
        try testing.expectEqualSlices(u8, want, w.buffered());
        // The canonical form passes the deterministic decoder ...
        const back = try cbor.decode(a, want, .{ .deterministic = true });
        try testing.expect(back == .f16 or back == .f32 or back == .f64);
        // ... and an 8-byte encoding of a value that has a shorter one does
        // not (RFC 8949 §4.2.1: the shortest form that keeps the value).
        var long: [9]u8 = undefined;
        long[0] = 0xfb;
        std.mem.writeInt(u64, long[1..9], f.bits, .big);
        if (want.len < 9) {
            try testing.expectError(error.NotDeterministic, cbor.decode(a, &long, .{ .deterministic = true }));
        } else {
            _ = try cbor.decode(a, &long, .{ .deterministic = true });
        }
    }
    // A binary32/16 value shrinks too (RFC 8949 Appendix A: 1.5 is f93e00).
    const got = try cbor.encode(a, .{ .f32 = 1.5 }, .{ .canonical = true });
    defer a.free(got);
    try testing.expectEqualSlices(u8, &unhex("f93e00"), got);
    // Without the option the width is kept, as before.
    const kept = try cbor.encode(a, .{ .f64 = 1.5 }, .{});
    defer a.free(kept);
    try testing.expectEqualSlices(u8, &unhex("fb3ff8000000000000"), kept);
}

test "trees: cbor2 output decodes and re-encodes byte for byte" {
    const a = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    for (cbor2.trees) |t| {
        const plain = try unhexAlloc(aa, t.plain_hex);
        const canon = try unhexAlloc(aa, t.canonical_hex);
        // cbor2's plain form writes every float as binary64 (or its NaN):
        // our encode keeps widths, so the bytes come back unchanged.
        const v = try cbor.decode(a, plain, .{});
        defer cbor.freeValue(a, v);
        const again = try cbor.encode(a, v, .{});
        defer a.free(again);
        try testing.expectEqualSlices(u8, plain, again);
        // The streaming writer produces the same bytes from the tree.
        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        try cbor.Writer.init(&aw.writer).value(v);
        try testing.expectEqualSlices(u8, plain, aw.written());
        // The reader walks the same item to its end.
        var r: cbor.Reader = .init(plain);
        try testing.expectEqualSlices(u8, plain, try r.rawValue(64));
        try testing.expectEqual(@as(?cbor.Token, null), try r.next());
        // cbor2's canonical form: floats in the shortest width. Its map
        // order is RFC 7049's (length first), not RFC 8949's bytewise, so
        // re-encode with shortest floats but WITHOUT sorting.
        const vc = try cbor.decode(a, canon, .{});
        defer cbor.freeValue(a, vc);
        const again_c = try cbor.encode(a, vc, .{ .shortest_floats = true });
        defer a.free(again_c);
        try testing.expectEqualSlices(u8, canon, again_c);
        // Diagnostic notation of any decoded tree succeeds.
        const d = try cbor.diagnostic(a, v);
        a.free(d);
    }
}

// ── strict decoding ────────────────────────────────────────────────────────

test "strict: duplicate keys and indefinite lengths agree with cbor2" {
    const a = testing.allocator;
    for (cbor2.verdicts) |vd| {
        const bytes = try unhexAlloc(a, vd.hex);
        defer a.free(bytes);
        errdefer std.debug.print("case: {s}\n", .{vd.what});
        if (vd.unique_keys_ok) {
            cbor.freeValue(a, try cbor.decode(a, bytes, .{ .reject_duplicate_keys = true }));
        } else {
            try testing.expectError(error.DuplicateKey, cbor.decode(a, bytes, .{ .reject_duplicate_keys = true }));
        }
        if (vd.definite_ok) {
            cbor.freeValue(a, try cbor.decode(a, bytes, .{ .reject_indefinite = true }));
        } else {
            try testing.expectError(error.NotDeterministic, cbor.decode(a, bytes, .{ .reject_indefinite = true }));
        }
        // Lenient decode accepts every one of them.
        cbor.freeValue(a, try cbor.decode(a, bytes, .{}));
    }
}

test "strict: deterministic decoding, case by case from RFC 8949 §4.2.1" {
    const a = testing.allocator;
    const det: cbor.DecodeOptions = .{ .deterministic = true };
    const ok = [_][]const u8{
        "17", "1818", "18ff", "190100", "19ffff", "1a00010000", "1b0000000100000000",
        "37",           "3818",                   "5818" ++ "00" ** 24, // a 24-byte string needs the 1-byte length
        "f93e00",       "fb3ff199999999999a",     "f97e00",
        "f90001",       "f97c00",                 "f98000",
        "fa47c35000",
        // keys strictly ascending, bytewise: 0x0a < 0x20 < 0x6162
          "a30a01200261620" ++ "3",
            // 1000 (19 03e8) sorts before "a" (61 61): bytewise, not length-first
        "a21903e8016161" ++ "02",
        "c11a514b67b0", "f8ff",                   "f0",
    };
    for (ok) |h| {
        const bytes = try unhexAlloc(a, h);
        defer a.free(bytes);
        const v = cbor.decode(a, bytes, det) catch |e| {
            std.debug.print("rejected {s}: {t}\n", .{ h, e });
            return e;
        };
        defer cbor.freeValue(a, v);
        // Accepted bytes are their own canonical encoding.
        const re = try cbor.encode(a, v, .{ .canonical = true });
        defer a.free(re);
        try testing.expectEqualSlices(u8, bytes, re);
    }
    const not_det = [_][]const u8{
        "1817", "190017", "1900ff", "1a0000ffff", "1b00000000ffffffff", // longer than needed
        "3817", "5801" ++ "61", "7801" ++ "61", "9800", "b800", "d80101", // lengths, tags too
        "fa3fc00000", "fb3ff8000000000000", "fa7f800000", // 1.5 / 1.5 / Infinity too wide
        "f97e01", "f9fe00", "fa7fc00000", "fb7ff8000000000000", // only f97e00 is NaN
        "a2200201" ++ "01", // keys 0x20 then 0x01: descending
        "a26161011903e8" ++ "02", // "a" before 1000: length-first order is not bytewise
        "9f01ff", "5f4101ff", "7f6161ff", "bf0101ff", // indefinite
    };
    for (not_det) |h| {
        const bytes = try unhexAlloc(a, h);
        defer a.free(bytes);
        testing.expectError(error.NotDeterministic, cbor.decode(a, bytes, det)) catch |e| {
            std.debug.print("accepted {s}\n", .{h});
            return e;
        };
        // Each is well-formed: the lenient decoder takes it.
        cbor.freeValue(a, try cbor.decode(a, bytes, .{}));
    }
    // Equal keys under `deterministic`: DuplicateKey, not an order error.
    try testing.expectError(error.DuplicateKey, cbor.decode(a, &unhex("a201010102"), det));
    // Nested maps are checked too (the inner map is out of order).
    try testing.expectError(error.NotDeterministic, cbor.decode(a, &unhex("a101a2020101" ++ "01"), det));
    // `strict_options` is the conjunction.
    try testing.expectError(error.DuplicateKey, cbor.decode(a, &unhex("a201010102"), cbor.strict_options));
}

test "canonical encode: keys bytewise, floats shortest — derived by hand" {
    const a = testing.allocator;
    // {"b": 1.5, 10: 100000.0, -1: 1.1}, every float a binary64 Value.
    // Encoded keys: "b" = 61 62, 10 = 0a, -1 = 20 -> order 0a, 20, 6162.
    // Values (RFC 8949 Appendix A): 100000.0 = fa47c35000,
    // 1.1 = fb3ff199999999999a, 1.5 = f93e00.
    const entries = [_]MapEntry{
        .{ .key = .{ .text = "b" }, .value = .{ .f64 = 1.5 } },
        .{ .key = .{ .uint = 10 }, .value = .{ .f64 = 100000.0 } },
        .{ .key = .{ .negint = 0 }, .value = .{ .f64 = 1.1 } },
    };
    const got = try cbor.encode(a, .{ .map = &entries }, .{ .canonical = true });
    defer a.free(got);
    try testing.expectEqualSlices(u8, &unhex("a30afa47c3500020fb3ff199999999999a6162f93e00"), got);
    // And it passes the strictest decoder.
    cbor.freeValue(a, try cbor.decode(a, got, cbor.strict_options));
}

test "strict: the duplicate-key scratch is freed on every path" {
    // reject_duplicate_keys allocates one encoding per key; a failing
    // allocation at any point must leave nothing behind.
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn f(a: std.mem.Allocator) !void {
            const v = cbor.decode(a, &unhex("a3616101a1010202616302"), .{ .reject_duplicate_keys = true }) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return e,
            };
            cbor.freeValue(a, v);
        }
    }.f, .{});
}

// ── CBOR Sequences (RFC 8742) ──────────────────────────────────────────────

test "sequence: items one by one, empty sequence, error leaves the position" {
    const a = testing.allocator;
    // RFC 8742 §2: a sequence is items back to back; the empty string is
    // the empty sequence.
    var empty: cbor.Sequence = .init(a, "", .{});
    try testing.expectEqual(@as(?Value, null), try empty.next());

    const bytes = unhex("0102820304");
    var s: cbor.Sequence = .init(a, &bytes, .{});
    try testing.expectEqual(@as(u64, 1), (try s.next()).?.uint);
    try testing.expectEqual(@as(u64, 2), (try s.next()).?.uint);
    const arr = (try s.next()).?;
    defer cbor.freeValue(a, arr);
    try testing.expectEqual(@as(usize, 2), arr.array.len);
    try testing.expectEqual(@as(?Value, null), try s.next());

    // A truncated third item: the first two come out, then the error, and
    // the position still points at the broken item.
    const bad = unhex("01028203");
    var sb: cbor.Sequence = .init(a, &bad, .{});
    _ = try sb.next();
    _ = try sb.next();
    try testing.expectError(error.Truncated, sb.next());
    try testing.expectEqual(@as(usize, 2), sb.pos);
}

// ── streaming reader / writer ──────────────────────────────────────────────

test "reader: tokens of RFC 8949 Appendix A's [_ 1, [2, 3], [_ 4, 5]] and a chunked string" {
    const bytes = unhex("9f018202039f0405ffff" ++ "5f42010243030405ff");
    var r: cbor.Reader = .init(&bytes);
    const T = cbor.Token;
    const want = [_]T{
        .{ .array = null }, .{ .uint = 1 },           .{ .array = 2 },              .{ .uint = 2 }, .{ .uint = 3 },
        .{ .array = null }, .{ .uint = 4 },           .{ .uint = 5 },               .break_code,    .break_code,
        .bytes_start,       .{ .bytes = "\x01\x02" }, .{ .bytes = "\x03\x04\x05" }, .break_code,
    };
    for (want) |w| {
        const got = (try r.next()).?;
        try testing.expectEqual(std.meta.activeTag(w), std.meta.activeTag(got));
        switch (w) {
            .uint => |u| try testing.expectEqual(u, got.uint),
            .array => |n| try testing.expectEqual(n, got.array),
            .bytes => |b| try testing.expectEqualSlices(u8, b, got.bytes),
            else => {},
        }
    }
    try testing.expectEqual(@as(?cbor.Token, null), try r.next());
}

test "reader: incremental — a token cut short waits for more input" {
    // 1000000 = 1a 000f4240 (RFC 8949 Appendix A). Feed it two bytes at a time.
    const full = unhex("1a000f4240" ++ "6449455446");
    var have: usize = 0;
    var r: cbor.Reader = .init(full[0..0]);
    var got: [2]cbor.Token = undefined;
    var n: usize = 0;
    while (n < 2) {
        if (r.next()) |t| {
            got[n] = t orelse {
                have = @min(full.len, have + 2);
                r.bytes = full[0..have];
                continue;
            };
            n += 1;
        } else |e| {
            try testing.expectEqual(error.Truncated, e);
            have = @min(full.len, have + 2);
            const pos = r.pos;
            r.bytes = full[0..have];
            try testing.expectEqual(pos, r.pos); // nothing was consumed
        }
    }
    try testing.expectEqual(@as(u64, 1000000), got[0].uint);
    try testing.expectEqualStrings("IETF", got[1].text);
}

test "reader: skipValue gives decode's verdict on hostile inputs" {
    const a = testing.allocator;
    const cases = [_][]const u8{
        "",                 "18",               "1c",       "1f",                 "ff",   "f818",   "5f01ff", "5f5fff", "7f4100ff", "61ff", "7f61ff",
        "82",               "8201",             "9f01",     "a1",                 "a101", "bf01ff", "c1",     "5f41",   "5f4200",   "5f1c", "5f19",
        "81" ** 70 ++ "01", "c1" ** 70 ++ "01", "5f4101ff", "a26161016162820203",
    };
    for (cases) |h| {
        const bytes = try unhexAlloc(a, h);
        defer a.free(bytes);
        var r: cbor.Reader = .init(bytes);
        const skipped = r.skipValue(64);
        const decoded = cbor.decodePrefix(a, bytes, .{});
        if (decoded) |p| {
            defer cbor.freeValue(a, p.value);
            try skipped;
            try testing.expectEqual(p.len, r.pos);
        } else |e| {
            testing.expectError(e, skipped) catch |err| {
                std.debug.print("case {s}\n", .{h});
                return err;
            };
            try testing.expectEqual(@as(usize, 0), r.pos);
        }
    }
}

test "writer: into a caller buffer, indefinite items, overflow is an error" {
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const cw = cbor.Writer.init(&w);
    // RFC 8949 Appendix A: [_ 1, [2, 3], [_ 4, 5]] = 9f018202039f0405ffff
    try cw.beginArray(null);
    try cw.uint(1);
    try cw.beginArray(2);
    try cw.uint(2);
    try cw.uint(3);
    try cw.beginArray(null);
    try cw.uint(4);
    try cw.uint(5);
    try cw.end();
    try cw.end();
    try testing.expectEqualSlices(u8, &unhex("9f018202039f0405ffff"), w.buffered());

    // {_ "Fun": true, "Amt": -2} = bf6346756ef563416d7421ff, and
    // (_ "strea", "ming") = 7f657374726561646d696e67ff.
    var buf2: [64]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    const c2 = cbor.Writer.init(&w2);
    try c2.beginMap(null);
    try c2.text("Fun");
    try c2.boolean(true);
    try c2.text("Amt");
    try c2.int(-2);
    try c2.end();
    try c2.beginText();
    try c2.text("strea");
    try c2.text("ming");
    try c2.end();
    try testing.expectEqualSlices(u8, &unhex("bf6346756ef563416d7421ff" ++ "7f657374726561646d696e67ff"), w2.buffered());

    // Appendix A extremes through the writer: -18446744073709551616,
    // simple(16), simple(255), 1(1363896240), h'01020304'.
    var buf3: [64]u8 = undefined;
    var w3: std.Io.Writer = .fixed(&buf3);
    const c3 = cbor.Writer.init(&w3);
    try c3.negint(std.math.maxInt(u64));
    try c3.simple(16);
    try c3.simple(255);
    try c3.tag(1);
    try c3.uint(1363896240);
    try c3.bytes("\x01\x02\x03\x04");
    try c3.int(std.math.minInt(i64));
    try c3.null_();
    try c3.undefined_();
    try testing.expectEqualSlices(u8, &unhex("3bffffffffffffffff" ++ "f0" ++ "f8ff" ++ "c11a514b67b0" ++ "4401020304" ++ "3b7fffffffffffffff" ++ "f6f7"), w3.buffered());

    // A buffer too small: WriteFailed, never a write past its end.
    var tiny: [2]u8 = undefined;
    var wt: std.Io.Writer = .fixed(&tiny);
    try testing.expectError(error.WriteFailed, cbor.Writer.init(&wt).uint(1000));
}

// ── typed mapping ──────────────────────────────────────────────────────────

const Kind = enum(u8) { public = 1, private = 2 };

const Record = struct {
    id: u32,
    name: []const u8,
    hash: [4]u8,
    pub const cbor_options = .{ .keys = .{ .id = 1 } };
};

const Shape = union(enum) {
    circle: f64,
    point,
    poly: []const [2]i16,
};

const Big = struct {
    rec: Record,
    tags: []const []const u8,
    blob: []const u8,
    kind: Kind = .public,
    note: ?[]const u8 = null,
    shape: Shape,
    pair: struct { u8, bool },
    pub const cbor_options = .{
        .keys = .{ .rec = 1, .tags = 2, .blob = 3, .kind = 4, .note = "n" },
        .bytes = .{.blob},
    };
};

test "typed: encode derived by hand, decode back" {
    const a = testing.allocator;
    // Record{ .id = 7, .name = "x", .hash = 01020304 }, canonical:
    // keys 01 (id), "hash" (64 68617368), "name" (64 6e616d65); 01 < 64 68 < 64 6e.
    const r: Record = .{ .id = 7, .name = "x", .hash = .{ 1, 2, 3, 4 } };
    const bytes = try cbor.typed.encode(a, r, .{ .canonical = true });
    defer a.free(bytes);
    try testing.expectEqualSlices(u8, &unhex("a3" ++ "0107" ++ "64686173684401020304" ++ "646e616d65" ++ "6178"), bytes);
    const back = try cbor.typed.decode(Record, a, bytes, .{});
    defer back.deinit();
    try testing.expectEqual(@as(u32, 7), back.value.id);
    try testing.expectEqualStrings("x", back.value.name);
    try testing.expectEqualSlices(u8, &r.hash, &back.value.hash);
}

test "typed: every mapped kind round-trips; defaults, optionals, unions" {
    const a = testing.allocator;
    const big: Big = .{
        .rec = .{ .id = 1, .name = "n", .hash = .{ 9, 9, 9, 9 } },
        .tags = &.{ "a", "\u{6c34}" },
        .blob = "\x00\xff",
        .kind = .private,
        .shape = .{ .poly = &.{ .{ -1, 2 }, .{ 300, -300 } } },
        .pair = .{ 5, true },
    };
    const bytes = try cbor.typed.encode(a, big, .{});
    defer a.free(bytes);
    // The note is null: omitted, so the map has 6 entries (a6), in field order.
    try testing.expectEqual(@as(u8, 0xa6), bytes[0]);
    const p = try cbor.typed.decode(Big, a, bytes, .{});
    defer p.deinit();
    const v = p.value;
    try testing.expectEqualStrings("n", v.rec.name);
    try testing.expectEqualStrings("\u{6c34}", v.tags[1]);
    try testing.expectEqualSlices(u8, "\x00\xff", v.blob);
    try testing.expectEqual(Kind.private, v.kind);
    try testing.expectEqual(@as(?[]const u8, null), v.note);
    try testing.expectEqual(@as(i16, -300), v.shape.poly[1][1]);
    try testing.expectEqual(@as(u8, 5), v.pair[0]);
    try testing.expect(v.pair[1]);

    // Diagnostic of the encoding, written out by hand from the field
    // declarations: keys 1..4 ints, the union a one-entry map, enum = 2.
    const dv = try cbor.decode(a, bytes, .{});
    defer cbor.freeValue(a, dv);
    const d = try cbor.diagnostic(a, dv);
    defer a.free(d);
    try testing.expectEqualStrings(
        "{1: {1: 1, \"name\": \"n\", \"hash\": h'09090909'}, 2: [\"a\", \"\\u6c34\"], 3: h'00ff', 4: 2, " ++
            "\"shape\": {\"poly\": [[-1, 2], [300, -300]]}, \"pair\": [5, true]}",
        d,
    );

    // A union's void variant is null; a missing defaulted field takes its default.
    const s = try cbor.typed.encode(a, @as(Shape, .point), .{});
    defer a.free(s);
    try testing.expectEqualSlices(u8, &unhex("a165706f696e74f6"), s);
    // {"x": 1} into a struct whose `y` defaults to 5 and `z` is optional.
    const D = struct { x: u8, y: u8 = 5, z: ?u8 };
    const pd = try cbor.typed.decode(D, a, &unhex("a1617801"), .{});
    defer pd.deinit();
    try testing.expectEqual(@as(u8, 5), pd.value.y);
    try testing.expectEqual(@as(?u8, null), pd.value.z);
    // An enum also decodes from its tag name.
    const pk = try cbor.typed.decode(Kind, a, &unhex("667075626c6963"), .{});
    defer pk.deinit();
    try testing.expectEqual(Kind.public, pk.value);
}

test "typed: every refusal, each derived from the type and the bytes" {
    const a = testing.allocator;
    const S = struct { a: u8 };
    const T = cbor.typed;
    // Missing required field: {} -> MissingField.
    try testing.expectError(error.MissingField, T.decode(S, a, &unhex("a0"), .{}));
    // {"a": 256}: 256 does not fit u8.
    try testing.expectError(error.Overflow, T.decode(S, a, &unhex("a16161190100"), .{}));
    // {"a": -1}: negative into unsigned.
    try testing.expectError(error.Overflow, T.decode(S, a, &unhex("a1616120"), .{}));
    // {"a": "x"}: text where an integer is wanted.
    try testing.expectError(error.WrongType, T.decode(S, a, &unhex("a161616178"), .{}));
    // {"a": 1, "a": 2}: one field named twice (lenient CBOR, strict mapping).
    try testing.expectError(error.DuplicateField, T.decode(S, a, &unhex("a26161016161" ++ "02"), .{}));
    // {"a": 1, "b": 2}: unknown key, ignored by default, refused on request.
    const ok = try T.decode(S, a, &unhex("a26161016162" ++ "02"), .{});
    ok.deinit();
    try testing.expectError(error.UnknownField, T.decode(S, a, &unhex("a26161016162" ++ "02"), .{ .ignore_unknown_fields = false }));
    // [4]u8 from a 3-byte string.
    try testing.expectError(error.LengthMismatch, T.decode([4]u8, a, &unhex("43010203"), .{}));
    // A tuple of two from an array of three.
    try testing.expectError(error.LengthMismatch, T.decode(struct { u8, u8 }, a, &unhex("83010203"), .{}));
    // Enum value 3 is no member of Kind; the name "secret" neither.
    try testing.expectError(error.InvalidEnum, T.decode(Kind, a, &unhex("03"), .{}));
    try testing.expectError(error.InvalidEnum, T.decode(Kind, a, &unhex("66736563726574"), .{}));
    // A union map naming no variant, and one with two entries.
    try testing.expectError(error.InvalidEnum, T.decode(Shape, a, &unhex("a1617801"), .{}));
    try testing.expectError(error.WrongType, T.decode(Shape, a, &unhex("a2657" ++ "0" ++ "6f696e74f6617801"), .{}));
    // f32 from binary64 1.1 (not exact in binary32), but 1.5 is.
    try testing.expectError(error.Overflow, T.decode(f32, a, &unhex("fb3ff199999999999a"), .{}));
    const f = try T.decode(f32, a, &unhex("fb3ff8000000000000"), .{});
    f.deinit();
    // A text field from a byte string, and a bytes field from a text.
    try testing.expectError(error.WrongType, T.decode([]const u8, a, &unhex("4161"), .{}));
    try testing.expectError(error.WrongType, T.decode(Big, a, &unhex("a1036161"), .{}));
    // The CBOR itself is still checked first.
    try testing.expectError(error.Truncated, T.decode(S, a, &unhex("a16161"), .{}));
    try testing.expectError(error.DuplicateKey, T.decode(S, a, &unhex("a26161016161" ++ "02"), .{ .decode = .{ .reject_duplicate_keys = true } }));
    // i8 limits: -128 (37 7f... is 0x387f) fits, -129 (0x3880) does not.
    const lo = try T.decode(i8, a, &unhex("387f"), .{});
    defer lo.deinit();
    try testing.expectEqual(@as(i8, -128), lo.value);
    try testing.expectError(error.Overflow, T.decode(i8, a, &unhex("3880"), .{}));
    // u64 max and the most negative CBOR integer into i64.
    try testing.expectError(error.Overflow, T.decode(i64, a, &unhex("3bffffffffffffffff"), .{}));
}

test "typed: no leak on any allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn f(a: std.mem.Allocator) !void {
            const bytes = unhex("a3" ++ "0107" ++ "64686173684401020304" ++ "646e616d65" ++ "6178");
            const p = try cbor.typed.decode(Record, a, &bytes, .{});
            p.deinit();
            const e = try cbor.typed.encode(a, Record{ .id = 1, .name = "q", .hash = @splat(0) }, .{ .canonical = true });
            a.free(e);
        }
    }.f, .{});
}

// ── tests asked for by the 2026-10-04 mutation run ─────────────────────────

test "reader: an indefinite TEXT string opens with text_start, not bytes_start" {
    // RFC 8949 Appendix A: (_ "strea", "ming") = 7f 65 7374726561 64 6d696e67 ff.
    const bytes = unhex("7f657374726561646d696e67ff");
    var r: cbor.Reader = .init(&bytes);
    try testing.expectEqual(cbor.Token.text_start, (try r.next()).?);
    try testing.expectEqualStrings("strea", (try r.next()).?.text);
    try testing.expectEqualStrings("ming", (try r.next()).?.text);
    try testing.expectEqual(cbor.Token.break_code, (try r.next()).?);
}

test "diag: float layout at ECMAScript's switch points (derived by hand)" {
    const a = testing.allocator;
    // Number::toString: plain digits while the point position n <= 21,
    // exponent form from 1e21; "0.000..." while n > -6, exponent from 1e-7.
    // The RFC's ".0" goes on any mantissa without a point.
    const cases = [_]struct { x: f64, want: []const u8 }{
        .{ .x = 1e20, .want = "100000000000000000000.0" },
        .{ .x = 123456789012345680000.0, .want = "123456789012345680000.0" },
        .{ .x = 1e21, .want = "1.0e+21" },
        .{ .x = 1.5e21, .want = "1.5e+21" },
        .{ .x = 1e-6, .want = "0.000001" },
        .{ .x = 1.25e-6, .want = "0.00000125" },
        .{ .x = 1e-7, .want = "1.0e-7" },
        .{ .x = -2.5e-7, .want = "-2.5e-7" },
        .{ .x = 0.5, .want = "0.5" },
    };
    for (cases) |c| {
        const got = try cbor.diagnostic(a, .{ .f64 = c.x });
        defer a.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
}

test "typed: negative integer keys, as COSE labels use them (derived by hand)" {
    const a = testing.allocator;
    // An EC2-shaped COSE_Key subset: kty (1) = 2, crv (-1) = 1, x (-2) = h'aabb'.
    // Canonical key order is bytewise on 01, 20, 21.
    const Key = struct {
        kty: u8,
        crv: u8,
        x: []const u8,
        pub const cbor_options = .{ .keys = .{ .kty = 1, .crv = -1, .x = -2 }, .bytes = .{.x} };
    };
    const want = unhex("a3" ++ "0102" ++ "2001" ++ "2142aabb");
    const got = try cbor.typed.encode(a, Key{ .kty = 2, .crv = 1, .x = "\xaa\xbb" }, .{ .canonical = true });
    defer a.free(got);
    try testing.expectEqualSlices(u8, &want, got);
    const p = try cbor.typed.decode(Key, a, &want, .{});
    defer p.deinit();
    try testing.expectEqual(@as(u8, 1), p.value.crv);
    try testing.expectEqualSlices(u8, "\xaa\xbb", p.value.x);
}

test "typed: the allocation cap stops a small input from becoming a huge T" {
    const a = testing.allocator;
    // Each `a0` (one byte, an empty map) becomes a whole Fat of defaults:
    // 100 of them ask for 100 * @sizeOf(Fat) bytes, over a 100 000-byte cap.
    const Fat = struct { a: u8 = 0, pad: [4096]u8 = @splat(0) };
    var input: [102]u8 = undefined;
    input[0] = 0x98; // array, 1-byte count
    input[1] = 100;
    @memset(input[2..], 0xa0);
    try testing.expectError(error.TooLarge, cbor.typed.decode([]const Fat, a, &input, .{ .max_alloc_bytes = 100_000 }));
    // The default cap (64 MiB) lets the same 410 KB through.
    const p = try cbor.typed.decode([]const Fat, a, &input, .{});
    defer p.deinit();
    try testing.expectEqual(@as(usize, 100), p.value.len);
    // A count times a size that overflows usize is refused, not wrapped.
    try testing.expectError(error.TooLarge, cbor.typed.decode([]const Fat, a, &input, .{ .max_alloc_bytes = 0 }));
}
