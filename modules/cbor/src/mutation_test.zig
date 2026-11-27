// SPDX-License-Identifier: MIT
//! Tests asked for by the 2026-11-27 whole-module mutation run. Every
//! expected value is derived from RFC 8949 / RFC 9052 / the module's own
//! documented contract, never from what the code printed.

const std = @import("std");
const testing = std.testing;
const cbor = @import("root.zig");
const cose = cbor.cose;
const stream = cbor.stream;
const T = cbor.typed;
const Value = cbor.Value;
const MapEntry = cbor.MapEntry;

/// The bytes of a hex literal, as a pointer to static (comptime) storage.
fn hx(comptime h: []const u8) *const [h.len / 2]u8 {
    const out = comptime blk: {
        var o: [h.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&o, h) catch unreachable;
        break :blk o;
    };
    return &out;
}

/// A push-decoder handler that records the last simple value and the text
/// bytes it was given.
const Sink = struct {
    events: usize = 0,
    simple: ?u8 = null,
    text: [32]u8 = undefined,
    text_len: usize = 0,

    pub fn event(self: *Sink, ev: stream.Event) error{}!void {
        self.events += 1;
        switch (ev) {
            .token => |t| switch (t) {
                .simple => |s| self.simple = s,
                else => {},
            },
            .text => |p| {
                @memcpy(self.text[self.text_len..][0..p.data.len], p.data);
                self.text_len += p.data.len;
            },
            else => {},
        }
    }
};

// ── root.zig ───────────────────────────────────────────────────────────────

test "mutation 2026-11-27: fromI64 maps 0 to uint 0, -1 to negint 0, i64 min to negint maxInt(i64)" {
    const z = Value.fromI64(0);
    try testing.expect(z == .uint);
    try testing.expectEqual(@as(u64, 0), z.uint);
    const m1 = Value.fromI64(-1);
    try testing.expect(m1 == .negint);
    try testing.expectEqual(@as(u64, 0), m1.negint);
    const lo = Value.fromI64(std.math.minInt(i64));
    try testing.expect(lo == .negint);
    try testing.expectEqual(@as(u64, std.math.maxInt(i64)), lo.negint);
    try testing.expectEqual(@as(?i64, std.math.minInt(i64)), lo.toI64());
}

test "mutation 2026-11-27: a bignum of exactly 8 significant bytes is not preferred (RFC 8949 section 3.4.3)" {
    // 8 bytes with a non-zero first byte fit major type 0/1: the integer is
    // the preferred serialization, so the bignum form is NotDeterministic.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const bad = [_][]const u8{
        hx("c248ffffffffffffffff"),
        hx("c2480100000000000000"),
        hx("c348ffffffffffffffff"),
    };
    for (bad) |b| try testing.expectError(error.NotDeterministic, cbor.decode(arena.allocator(), b, .{ .deterministic = true }));
    // Nine significant bytes is the smallest preferred bignum.
    _ = try cbor.decode(arena.allocator(), hx("c249010000000000000000"), .{ .deterministic = true });
}

test "mutation 2026-11-27: simple(24 n) accepts exactly n >= 32 (RFC 8949 section 3.3), in decode, Reader and PushDecoder" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // decode
    const v = try cbor.decode(a, hx("f820"), .{});
    try testing.expectEqual(@as(u8, 32), v.simple);
    try testing.expectError(error.Malformed, cbor.decode(a, hx("f81f"), .{}));
    try testing.expectError(error.Malformed, cbor.decode(a, hx("f818"), .{}));
    // Reader
    var r = cbor.Reader.init(hx("f820"));
    try testing.expectEqual(@as(u8, 32), (try r.next()).?.simple);
    var r2 = cbor.Reader.init(hx("f81f"));
    try testing.expectError(error.Malformed, r2.next());
    // PushDecoder, whole and split between the head byte and the argument
    var d = stream.PushDecoder(4).init();
    var s: Sink = .{};
    try d.feed(hx("f820"), &s);
    try testing.expectEqual(@as(?u8, 32), s.simple);
    var d2 = stream.PushDecoder(4).init();
    var s2: Sink = .{};
    try d2.feed(hx("f8"), &s2);
    try testing.expectError(error.Malformed, d2.feed(hx("1f"), &s2));
    var d3 = stream.PushDecoder(4).init();
    var s3: Sink = .{};
    try testing.expectError(error.Malformed, d3.feed(hx("f81f"), &s3));
}

test "mutation 2026-11-27: simple 19 is one byte, 32 and 255 two; 20..31 have no encoding (RFC 8949 section 3.3)" {
    const a = testing.allocator;
    const s19 = try cbor.encode(a, .{ .simple = 19 }, .{});
    defer a.free(s19);
    try testing.expectEqualSlices(u8, hx("f3"), s19);
    const s32 = try cbor.encode(a, .{ .simple = 32 }, .{});
    defer a.free(s32);
    try testing.expectEqualSlices(u8, hx("f820"), s32);
    const s255 = try cbor.encode(a, .{ .simple = 255 }, .{});
    defer a.free(s255);
    try testing.expectEqualSlices(u8, hx("f8ff"), s255);
    // 20..23 are false/true/null/undefined (their own Value variants), 24..31
    // reserved: the one-byte form f4..f7/f8.. and the two-byte form f8 14..f8 1f
    // are both wrong for a `.simple`, and the decoder refuses the latter.
    var v: u8 = 20;
    while (v < 32) : (v += 1) {
        try testing.expectError(error.InvalidSimpleValue, cbor.encode(a, .{ .simple = v }, .{}));
        try testing.expectError(error.InvalidSimpleValue, cbor.encode(a, .{ .simple = v }, .{ .canonical = true }));
    }
    // The push Writer does the same, and writes nothing for a refused value.
    var buf: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const wr = cbor.Writer.init(&w);
    try wr.simple(19);
    try testing.expectError(error.InvalidSimpleValue, wr.simple(20));
    try testing.expectError(error.InvalidSimpleValue, wr.value(.{ .simple = 31 }));
    try wr.simple(32);
    try testing.expectEqualSlices(u8, hx("f3f820"), w.buffered());
}

test "mutation 2026-11-27: indefinite map frees a decoded key and value on every allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn f(a: std.mem.Allocator) !void {
            // {_ "a": "b", "c": "d"}: text keys and values own heap memory.
            const v = try cbor.decode(a, hx("bf6161616261636164ff"), .{});
            cbor.freeValue(a, v);
        }
    }.f, .{});
}

// ── stream.zig: Reader ─────────────────────────────────────────────────────

test "mutation 2026-11-27: Reader.peek at the end is null; an infinite-length argument on major 0/1 is Malformed" {
    var r = cbor.Reader.init(hx("01"));
    try testing.expect((try r.peek()).? == .uint);
    _ = try r.next();
    try testing.expect((try r.peek()) == null);
    try testing.expect((try r.next()) == null);
    var empty = cbor.Reader.init("");
    try testing.expect((try empty.peek()) == null);
    // 0x1f (uint), 0x3f (negint) and 0xdf (tag) carry no indefinite length.
    inline for (.{ "1f", "3f", "df" }) |h| {
        var rr = cbor.Reader.init(hx(h));
        try testing.expectError(error.Malformed, rr.next());
        try testing.expectError(error.Malformed, rr.peek());
    }
}

test "mutation 2026-11-27: Reader simple(24 n) boundary at 32" {
    var r = cbor.Reader.init(hx("f820"));
    try testing.expectEqual(@as(u8, 32), (try r.peek()).?.simple);
    var r2 = cbor.Reader.init(hx("f81f"));
    try testing.expectError(error.Malformed, r2.next());
    var r3 = cbor.Reader.init(hx("f81e"));
    try testing.expectError(error.Malformed, r3.next());
}

test "mutation 2026-11-27: skipValue over indefinite strings, arrays and maps agrees with decodePrefix" {
    const a = testing.allocator;
    const cases = [_][]const u8{
        hx("5f"), // cut right after the opener
        hx("7f"),
        hx("5f41"), // a chunk cut short
        hx("9f"),
        hx("9f01"), // no break
        hx("9f01ff"), // [_ 1]
        hx("9fff"), // [_ ]
        hx("9f9f01ffff"), // [_ [_ 1]]
        hx("bf0102ff"), // {_ 1: 2}
        hx("bfff"), // {_ }
        hx("bf01ff"), // a key without its value
        hx("bf010203ff"), // {_ 1: 2, 3: ...} cut: break where a value is due
        hx("9f01ff02"), // an item followed by more bytes
        hx("bf6161bf0102ffff"), // {_ "a": {_ 1: 2}}
    };
    for (cases) |bytes| {
        var r = cbor.Reader.init(bytes);
        const skipped = r.skipValue(64);
        if (cbor.decodePrefix(a, bytes, .{})) |p| {
            defer cbor.freeValue(a, p.value);
            try skipped;
            try testing.expectEqual(p.len, r.pos);
        } else |e| {
            try testing.expectError(e, skipped);
            try testing.expectEqual(@as(usize, 0), r.pos);
        }
    }
    // The exact byte count of an indefinite array and of the item after it.
    var r = cbor.Reader.init(hx("9f01ff02"));
    const raw = try r.rawValue(64);
    try testing.expectEqualSlices(u8, hx("9f01ff"), raw);
    try testing.expectEqual(@as(usize, 3), r.pos);
    try testing.expectEqual(@as(u64, 2), (try r.next()).?.uint);
}

// ── stream.zig: PushDecoder ────────────────────────────────────────────────

test "mutation 2026-11-27: PushDecoder.atBoundary is false once the decoder is dead" {
    var d = stream.PushDecoder(4).init();
    var s: Sink = .{};
    try testing.expect(d.atBoundary());
    try d.feed(hx("18"), &s);
    try testing.expect(!d.atBoundary()); // inside a head
    try d.feed(hx("05"), &s);
    try testing.expect(d.atBoundary());
    // A break with nothing open is refused; no head, body or frame is pending,
    // yet the decoder is unusable (documented: "After an error the decoder is
    // unusable"), so it is not "between items".
    try testing.expectError(error.Malformed, d.feed(hx("ff"), &s));
    try testing.expect(!d.atBoundary());
    try testing.expectError(error.Malformed, d.finish());
}

test "mutation 2026-11-27: a stray break at nframes == max_depth is Malformed, not DepthLimitExceeded" {
    // [[ ... : two open counted arrays, max_depth 2: a break closes neither.
    var d = stream.PushDecoder(2).init();
    var s: Sink = .{};
    try d.feed(hx("8181"), &s);
    try testing.expectError(error.Malformed, d.feed(hx("ff"), &s));
    // Reader.skipValue gives the same verdict for the same bytes.
    var r = cbor.Reader.init(hx("8181ff"));
    try testing.expectError(error.Malformed, r.skipValue(2));
    // A third nested array is over the cap, and is reported as such.
    var d2 = stream.PushDecoder(2).init();
    var s2: Sink = .{};
    try testing.expectError(error.DepthLimitExceeded, d2.feed(hx("818181"), &s2));
}

test "mutation 2026-11-27: PushDecoder refuses 0x1f, 0x3f and 0xdf (no indefinite length on major 0, 1, 6)" {
    inline for (.{ "1f", "3f", "df" }) |h| {
        var d = stream.PushDecoder(4).init();
        var s: Sink = .{};
        try testing.expectError(error.Malformed, d.feed(hx(h), &s));
        try testing.expectEqual(@as(usize, 0), s.events);
    }
}

test "mutation 2026-11-27: a code point split across feeds is validated as a whole" {
    // 63 e2 | 82 41: the euro sign's lead byte, then a continuation and a
    // byte that is no continuation: ill-formed.
    var d = stream.PushDecoder(4).init();
    var s: Sink = .{};
    try d.feed(hx("63e2"), &s);
    try testing.expectError(error.Malformed, d.feed(hx("8241"), &s));
    // Control: the real euro sign (e2 82 ac) split the same way arrives whole.
    var d2 = stream.PushDecoder(4).init();
    var s2: Sink = .{};
    try d2.feed(hx("63e2"), &s2);
    try d2.feed(hx("82ac"), &s2);
    try d2.finish();
    try testing.expectEqualSlices(u8, "\xe2\x82\xac", s2.text[0..s2.text_len]);
}

// ── stream.zig: Writer ─────────────────────────────────────────────────────

test "mutation 2026-11-27: Writer.int(0) is major 0, beginBytes is 5f, simple 19/20/32" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const wr = cbor.Writer.init(&w);
    try wr.int(0);
    try wr.int(-1);
    try wr.int(1);
    try wr.beginBytes();
    try testing.expectEqualSlices(u8, hx("00" ++ "20" ++ "01" ++ "5f"), w.buffered());
    var buf2: [16]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    const wr2 = cbor.Writer.init(&w2);
    try wr2.simple(19);
    try testing.expectError(error.InvalidSimpleValue, wr2.simple(20));
    try wr2.simple(32);
    try testing.expectEqualSlices(u8, hx("f3" ++ "f820"), w2.buffered());
}

// ── cose.zig ───────────────────────────────────────────────────────────────

test "mutation 2026-11-27: equal negative labels beyond i64 are duplicates (RFC 9052 section 3)" {
    const big: u64 = std.math.maxInt(u64);
    const dup = [_]MapEntry{
        .{ .key = .{ .negint = big }, .value = .{ .uint = 1 } },
        .{ .key = .{ .negint = big }, .value = .{ .uint = 2 } },
    };
    try testing.expectError(error.DuplicateLabel, cose.checkLabels(&dup));
    // Control: neighbours, and the same magnitude as a uint, are different labels.
    const ok = [_]MapEntry{
        .{ .key = .{ .negint = big }, .value = .{ .uint = 1 } },
        .{ .key = .{ .negint = big - 1 }, .value = .{ .uint = 2 } },
        .{ .key = .{ .uint = big }, .value = .{ .uint = 3 } },
    };
    try cose.checkLabels(&ok);
}

test "mutation 2026-11-27: parseKey refuses an alg that is not an i64, and an AKP key with an EC/OKP alg" {
    // alg as text, and alg as a uint past i64: WrongType, not "absent".
    const bad_alg_text = [_]MapEntry{
        .{ .key = Value.fromI64(cose.label_kty), .value = Value.fromI64(cose.kty_okp) },
        .{ .key = Value.fromI64(cose.label_alg), .value = .{ .text = "x" } },
    };
    try testing.expectError(error.WrongType, cose.parseKey(.{ .map = &bad_alg_text }));
    const bad_alg_big = [_]MapEntry{
        .{ .key = Value.fromI64(cose.label_kty), .value = Value.fromI64(cose.kty_okp) },
        .{ .key = Value.fromI64(cose.label_alg), .value = .{ .uint = @as(u64, 1) << 63 } },
    };
    try testing.expectError(error.WrongType, cose.parseKey(.{ .map = &bad_alg_big }));
    // kty AKP with each registered EC/OKP signature alg: AlgKtyMismatch (RFC 9964).
    inline for (.{ cose.alg_es256, cose.alg_es384, cose.alg_es512, cose.alg_eddsa }) |alg| {
        const e = [_]MapEntry{
            .{ .key = Value.fromI64(cose.label_kty), .value = Value.fromI64(cose.kty_akp) },
            .{ .key = Value.fromI64(cose.label_alg), .value = Value.fromI64(alg) },
        };
        try testing.expectError(error.AlgKtyMismatch, cose.parseKey(.{ .map = &e }));
    }
}

test "mutation 2026-11-27: encodeOkpKey carries alg when present, omits it when absent" {
    const a = testing.allocator;
    const with = try cose.encodeOkpKey(a, .{ .alg = cose.alg_eddsa, .crv = cose.crv_ed25519, .x = "xx" });
    defer a.free(with.map);
    try testing.expectEqual(@as(usize, 4), with.map.len); // kty, alg, crv, x
    try testing.expectEqual(@as(?i64, cose.label_alg), with.map[1].key.toI64());
    try testing.expectEqual(@as(?i64, cose.alg_eddsa), with.map[1].value.toI64());
    const without = try cose.encodeOkpKey(a, .{ .alg = null, .crv = cose.crv_ed25519, .x = "xx" });
    defer a.free(without.map);
    try testing.expectEqual(@as(usize, 3), without.map.len);
}

test "mutation 2026-11-27: only the serialized empty map a0 stands for an empty protected header in the signed structures" {
    const a = testing.allocator;
    const head = hx("84" ++ "6a5369676e617475726531"); // [ "Signature1",
    const cases = [_]struct { protected: []const u8, want: []const u8 }{
        .{ .protected = "", .want = hx("40") },
        .{ .protected = "\xa0", .want = hx("40") }, // the empty map: as a zero-length bstr
        .{ .protected = "\x01", .want = hx("4101") }, // one byte, not a0: verbatim
        .{ .protected = "\xa0\x00", .want = hx("42a000") }, // starts with a0, longer: verbatim
        .{ .protected = "\xa1\x01\x26", .want = hx("43a10126") },
    };
    for (cases) |c| {
        const got = try cose.sigStructure(a, c.protected, "", "");
        defer a.free(got);
        try testing.expectEqualSlices(u8, head, got[0..head.len]);
        // protected, then the empty external_aad and payload (0x40 each)
        try testing.expectEqualSlices(u8, c.want, got[head.len .. got.len - 2]);
        try testing.expectEqualSlices(u8, hx("4040"), got[got.len - 2 ..]);
    }
    // signStructure: body and signer protected, each judged on its own.
    const sig_head = hx("85" ++ "695369676e6174757265"); // [ "Signature",
    const pairs = [_]struct { body: []const u8, signer: []const u8, want: []const u8 }{
        .{ .body = "\xa0", .signer = "\x01", .want = hx("40" ++ "4101") },
        .{ .body = "\x01", .signer = "\xa0", .want = hx("4101" ++ "40") },
        .{ .body = "\xa0", .signer = "\xa0", .want = hx("40" ++ "40") },
    };
    for (pairs) |c| {
        const got = try cose.signStructure(a, c.body, c.signer, "", "");
        defer a.free(got);
        try testing.expectEqualSlices(u8, sig_head, got[0..sig_head.len]);
        try testing.expectEqualSlices(u8, c.want, got[sig_head.len .. got.len - 2]);
        try testing.expectEqualSlices(u8, hx("4040"), got[got.len - 2 ..]);
    }
    // MAC0 and Encrypt0 use the same rule.
    const mac = try cose.macStructure(a, "\xa0", "", "");
    defer a.free(mac);
    try testing.expectEqualSlices(u8, hx("84" ++ "644d41433040" ++ "4040"), mac);
}

test "mutation 2026-11-27: COSE arrays of the wrong length are refused with the structure's own error, long and short" {
    const bs: Value = .{ .bytes = "" };
    const em: Value = .{ .map = &.{} };
    const nl: Value = .null_value;
    // COSE_Sign: exactly 4 elements.
    const sig_arr = [_]Value{.{ .array = &[_]Value{ bs, em, bs } }};
    const sign5 = [_]Value{ bs, em, nl, .{ .array = &sig_arr }, bs };
    try testing.expectError(error.NotSign, cose.parseSign(.{ .array = &sign5 }));
    // COSE_Signature: exactly 3.
    const sg4 = [_]Value{ bs, em, bs, nl };
    try testing.expectError(error.NotSign, cose.parseSignature(.{ .array = &sg4 }));
    const sg3 = [_]Value{ bs, em, bs };
    _ = try cose.parseSignature(.{ .array = &sg3 });
    // COSE_Mac0: exactly 4.
    const mac5 = [_]Value{ bs, em, bs, bs, bs };
    try testing.expectError(error.NotMac0, cose.parseMac0(.{ .array = &mac5 }));
    const mac4 = [_]Value{ bs, em, bs, bs };
    _ = try cose.parseMac0(.{ .array = &mac4 });
    // COSE_Encrypt0: exactly 3.
    const enc2 = [_]Value{ bs, em };
    try testing.expectError(error.NotEncrypt0, cose.parseEncrypt0(.{ .array = &enc2 }));
    const enc4 = [_]Value{ bs, em, bs, bs };
    try testing.expectError(error.NotEncrypt0, cose.parseEncrypt0(.{ .array = &enc4 }));
    const enc3 = [_]Value{ bs, em, bs };
    _ = try cose.parseEncrypt0(.{ .array = &enc3 });
}

test "mutation 2026-11-27: encodeSign leaves nothing allocated and writes the COSE_Sign array" {
    const a = testing.allocator;
    const sigs = [_]cose.Signature{.{ .protected = "", .unprotected = &.{}, .signature = "ab" }};
    const out = try cose.encodeSign(a, .{ .protected = "", .unprotected = &.{}, .payload = "x", .signatures = &sigs });
    defer a.free(out);
    // [ h'', {}, h'78', [ [ h'', {}, h'6162' ] ] ]
    try testing.expectEqualSlices(u8, hx("84" ++ "40" ++ "a0" ++ "4178" ++ "81" ++ "83" ++ "40" ++ "a0" ++ "426162"), out);
    // And on every allocation failure.
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn f(al: std.mem.Allocator) !void {
            const s = [_]cose.Signature{.{ .protected = "", .unprotected = &.{}, .signature = "ab" }};
            const o = try cose.encodeSign(al, .{ .protected = "", .unprotected = &.{}, .payload = null, .signatures = &s });
            al.free(o);
        }
    }.f, .{});
}

// ── typed.zig ──────────────────────────────────────────────────────────────

test "mutation 2026-11-27: max_alloc_bytes is spent as it is charged, and may be spent exactly" {
    const a = testing.allocator;
    // []const u32 from [1, 2]: 8 bytes. Exactly 8 passes, 7 does not.
    const ok = try T.decode([]const u32, a, hx("820102"), .{ .max_alloc_bytes = 8 });
    ok.deinit();
    try testing.expectError(error.TooLarge, T.decode([]const u32, a, hx("820102"), .{ .max_alloc_bytes = 7 }));
    // [[1, 2], [3, 4]] as []const []const u32: the outer slice (2 items) and
    // both inner ones draw on one budget.
    const total = 2 * @sizeOf([]const u32) + 4 * @sizeOf(u32);
    const nested = hx("82" ++ "820102" ++ "820304");
    const full = try T.decode([]const []const u32, a, nested, .{ .max_alloc_bytes = total });
    full.deinit();
    try testing.expectError(error.TooLarge, T.decode([]const []const u32, a, nested, .{ .max_alloc_bytes = total - 1 }));
    // A pointed-to item is charged its size, once.
    const p = try T.decode(*const u32, a, hx("01"), .{ .max_alloc_bytes = 4 });
    p.deinit();
    try testing.expectError(error.TooLarge, T.decode(*const u32, a, hx("01"), .{ .max_alloc_bytes = 3 }));
    // A copied (non-const) string is charged its length.
    const s = try T.decode([]u8, a, hx("63616263"), .{ .max_alloc_bytes = 3 });
    s.deinit();
    try testing.expectError(error.TooLarge, T.decode([]u8, a, hx("63616263"), .{ .max_alloc_bytes = 2 }));
}

test "mutation 2026-11-27: typed void and optional take undefined as they take null; NaN keeps any payload" {
    const a = testing.allocator;
    const v1 = try T.decode(void, a, hx("f6"), .{});
    v1.deinit();
    const v2 = try T.decode(void, a, hx("f7"), .{});
    v2.deinit();
    const o1 = try T.decode(?u8, a, hx("f7"), .{});
    defer o1.deinit();
    try testing.expectEqual(@as(?u8, null), o1.value);
    const o2 = try T.decode(?u8, a, hx("f6"), .{});
    defer o2.deinit();
    try testing.expectEqual(@as(?u8, null), o2.value);
    // A NaN is a NaN whatever its payload; f32 cannot hold this payload, and
    // that is not an overflow of a value that has no magnitude.
    const nan = try T.decode(f32, a, hx("fb7ff8000000000001"), .{});
    defer nan.deinit();
    try testing.expect(std.math.isNan(nan.value));
}

test "mutation 2026-11-27: fixed-size arrays and tuples need exactly their length, both ways" {
    const a = testing.allocator;
    try testing.expectError(error.LengthMismatch, T.decode([4]u8, a, hx("450102030405"), .{}));
    try testing.expectError(error.LengthMismatch, T.decode([3]u16, a, hx("820102"), .{}));
    try testing.expectError(error.LengthMismatch, T.decode([3]u16, a, hx("8401020304"), .{}));
    const ok = try T.decode([3]u16, a, hx("83010203"), .{});
    try testing.expectEqual([3]u16{ 1, 2, 3 }, ok.value);
    ok.deinit();
    try testing.expectError(error.LengthMismatch, T.decode(struct { u8, u8 }, a, hx("8101"), .{}));
    try testing.expectError(error.LengthMismatch, T.decode(struct { u8, u8 }, a, hx("83010203"), .{}));
}

test "mutation 2026-11-27: a matched field is not an unknown one; a union map has exactly one entry" {
    const a = testing.allocator;
    const S = struct { a: u8 };
    const strict: T.Options = .{ .ignore_unknown_fields = false };
    const ok = try T.decode(S, a, hx("a1616101"), strict);
    defer ok.deinit();
    try testing.expectEqual(@as(u8, 1), ok.value.a);
    try testing.expectError(error.UnknownField, T.decode(S, a, hx("a2616101616202"), strict));
    const U = union(enum) { x: u8, y: void };
    try testing.expectError(error.WrongType, T.decode(U, a, hx("a0"), .{}));
    try testing.expectError(error.WrongType, T.decode(U, a, hx("a2617801617900"), .{}));
    const u = try T.decode(U, a, hx("a1617805"), .{});
    defer u.deinit();
    try testing.expectEqual(@as(u8, 5), u.value.x);
}

test "mutation 2026-11-27: a bignum with leading zero bytes is read by value (RFC 8949 section 3.4.3)" {
    const a = testing.allocator;
    // 17 bytes: one zero, then sixteen 0xff: 2^128 - 1 fits u128.
    const ones = "ffffffffffffffffffffffffffffffff";
    const max = try T.decode(u128, a, hx("c251" ++ "00" ++ ones), .{});
    try testing.expectEqual(@as(u128, std.math.maxInt(u128)), max.value);
    max.deinit();
    // tag 3 with the same magnitude is -1 - (2^128 - 1) = -2^128: does not fit i128.
    try testing.expectError(error.Overflow, T.decode(i128, a, hx("c351" ++ "00" ++ ones), .{}));
    // tag 3 with a zero magnitude padded to 17 bytes is -1.
    const m1 = try T.decode(i128, a, hx("c351" ++ "00" ++ "00000000000000000000000000000000"), .{});
    try testing.expectEqual(@as(i128, -1), m1.value);
    m1.deinit();
    // 17 significant bytes are too many.
    try testing.expectError(error.Overflow, T.decode(u128, a, hx("c251" ++ "01" ++ ones), .{}));
}

test "mutation 2026-11-27: typed encode of 0, and of the 64-bit boundaries of a 128-bit integer" {
    const a = testing.allocator;
    var z: i32 = 0;
    _ = &z;
    const e0 = try T.encode(a, z, .{});
    defer a.free(e0);
    try testing.expectEqualSlices(u8, hx("00"), e0);
    var zb: i128 = 0;
    _ = &zb;
    const e1 = try T.encode(a, zb, .{});
    defer a.free(e1);
    try testing.expectEqualSlices(u8, hx("00"), e1);
    var zu: u128 = 0;
    _ = &zu;
    const e2 = try T.encode(a, zu, .{});
    defer a.free(e2);
    try testing.expectEqualSlices(u8, hx("00"), e2);
    // 2^64 - 1 is the largest major-0 argument; 2^64 is a bignum.
    var top: u128 = std.math.maxInt(u64);
    _ = &top;
    const e3 = try T.encode(a, top, .{});
    defer a.free(e3);
    try testing.expectEqualSlices(u8, hx("1bffffffffffffffff"), e3);
    var over: u128 = @as(u128, std.math.maxInt(u64)) + 1;
    _ = &over;
    const e4 = try T.encode(a, over, .{});
    defer a.free(e4);
    try testing.expectEqualSlices(u8, hx("c249010000000000000000"), e4);
    // -2^64 is the most negative major-1 value (argument 2^64 - 1); -2^64 - 1 is a bignum.
    var neg: i128 = -(@as(i128, 1) << 64);
    _ = &neg;
    const e5 = try T.encode(a, neg, .{});
    defer a.free(e5);
    try testing.expectEqualSlices(u8, hx("3bffffffffffffffff"), e5);
    var neg2: i128 = -(@as(i128, 1) << 64) - 1;
    _ = &neg2;
    const e6 = try T.encode(a, neg2, .{});
    defer a.free(e6);
    try testing.expectEqualSlices(u8, hx("c349010000000000000000"), e6);
}

test "mutation 2026-11-27: a string literal is text, a pointer-to-array field listed under bytes is a byte string" {
    const a = testing.allocator;
    const lit = try T.encode(a, "abc", .{});
    defer a.free(lit);
    try testing.expectEqualSlices(u8, hx("63616263"), lit);
    const B = struct {
        blob: *const [3]u8,
        pub const cbor_options = .{ .bytes = .{.blob} };
    };
    const b = try T.encode(a, B{ .blob = "abc" }, .{});
    defer a.free(b);
    // { "blob": h'616263' }
    try testing.expectEqualSlices(u8, hx("a1" ++ "64626c6f62" ++ "43616263"), b);
}

// ── diag.zig ───────────────────────────────────────────────────────────────

test "mutation 2026-11-27: diagnostic text is pure ASCII: non-ASCII as \\u escapes, pairs for supplementary planes" {
    const a = testing.allocator;
    const cases = [_]struct { text: []const u8, want: []const u8 }{
        .{ .text = "\xc3\xa9", .want = "\"\\u00e9\"" },
        .{ .text = "\xe2\x82\xac", .want = "\"\\u20ac\"" },
        .{ .text = "\xf0\x9f\x98\x80", .want = "\"\\ud83d\\ude00\"" },
    };
    for (cases) |c| {
        const got = try cbor.diagnostic(a, .{ .text = c.text });
        defer a.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
}

test "mutation 2026-11-27: diagnostic text escapes DEL (0x7f) as \\u007f" {
    const a = testing.allocator;
    const got = try cbor.diagnostic(a, .{ .text = "a\x7fb" });
    defer a.free(got);
    try testing.expectEqualStrings("\"a\\u007fb\"", got);
}
