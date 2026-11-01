// SPDX-License-Identifier: MIT

//! Tests added by the decoder-side mutation audit (2026-10-31, schemata over
//! decoder.zig, lzma_dec.zig and crc64.zig). Each test pins a behaviour the
//! older suite let a mutant change.
//!
//! The instrument is a symbol-level LZMA encoder (`SymEnc`) on top of
//! `RangeEncoder` and the decoder's own probability model: it can write any
//! symbol sequence, valid or not (a match one byte past the history, a
//! literal after the declared size, an end marker where none is allowed), and
//! it keeps the history, so the expected output of a valid stream is known
//! without a second decoder. An `.xz` builder writes the container by hand so
//! a single field (padding, index, footer, block header sizes) can be bent.

const std = @import("std");
const testing = std.testing;
const lzma = @import("root.zig");
const c = @import("common.zig");
const rcmod = @import("rangeenc.zig");
const xzfmt = @import("xzfmt.zig");

const gpa = testing.allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

// ── a symbol-level LZMA encoder ────────────────────────────────────────────

const SymEnc = struct {
    rc: rcmod.RangeEncoder = .{},
    p: *c.Probs,
    st: u8 = 0,
    rep: [4]u32 = .{ 0, 0, 0, 0 },
    hist: std.ArrayList(u8) = .empty,
    out: std.ArrayList(u8) = .empty,
    lc: u5,
    lp: u5,
    pb: u5,

    fn init(lc: u5, lp: u5, pb: u5) !SymEnc {
        const p = try gpa.create(c.Probs);
        p.reset(lc, lp);
        return .{ .p = p, .lc = lc, .lp = lp, .pb = pb };
    }

    fn deinit(e: *SymEnc) void {
        gpa.destroy(e.p);
        e.hist.deinit(gpa);
        e.out.deinit(gpa);
    }

    /// State, repeat distances and probabilities back to the start (LZMA2 0xA0).
    fn resetModel(e: *SymEnc) void {
        e.p.reset(e.lc, e.lp);
        e.st = 0;
        e.rep = .{ 0, 0, 0, 0 };
    }

    /// The dictionary is empty again (LZMA2 dictionary reset).
    fn resetDict(e: *SymEnc) void {
        e.hist.clearRetainingCapacity();
    }

    fn drain(e: *SymEnc) !void {
        var buf: [64]u8 = undefined;
        while (true) {
            var n: usize = 0;
            const full = e.rc.encode(&buf, &n);
            try e.out.appendSlice(gpa, buf[0..n]);
            if (!full) break;
        }
    }

    fn ps(e: *const SymEnc) usize {
        return e.hist.items.len & ((@as(usize, 1) << e.pb) - 1);
    }

    fn literal(e: *SymEnc, b: u8) !void {
        e.rc.bit(&e.p.is_match[e.st][e.ps()], 0);
        const pos = e.hist.items.len;
        const prev: usize = if (pos == 0) 0 else e.hist.items[pos - 1];
        const mask: usize = (@as(usize, 0x100) << e.lp) - (@as(usize, 0x100) >> e.lc);
        const sub = (((pos << 8) + prev) & mask) << e.lc;
        const probs = e.p.literal[sub * 3 ..][0..c.literal_coder_size];
        if (c.isLiteralState(e.st)) {
            e.rc.bittree(probs, 8, b);
        } else {
            var mwin: u32 = @as(u32, e.hist.items[pos - e.rep[0] - 1]) << 1;
            var offset: u32 = 0x100;
            var sym: u32 = 1;
            for (0..8) |k| {
                const bit: u32 = (b >> @intCast(7 - k)) & 1;
                const match_bit = mwin & offset;
                e.rc.bit(&probs[offset + match_bit + sym], bit);
                sym = (sym << 1) | bit;
                offset &= if (bit == 1) match_bit else ~match_bit;
                mwin <<= 1;
            }
        }
        e.st = c.updateLiteral(e.st);
        try e.hist.append(gpa, b);
        try e.drain();
    }

    fn encLen(e: *SymEnc, lp: *c.LenProbs, len: u32, ps_: usize) void {
        const l = len - 2;
        if (l < 8) {
            e.rc.bit(&lp.choice, 0);
            e.rc.bittree(&lp.low[ps_], 3, l);
        } else if (l < 16) {
            e.rc.bit(&lp.choice, 1);
            e.rc.bit(&lp.choice2, 0);
            e.rc.bittree(&lp.mid[ps_], 3, l - 8);
        } else {
            e.rc.bit(&lp.choice, 1);
            e.rc.bit(&lp.choice2, 1);
            e.rc.bittree(&lp.high, 8, l - 16);
        }
    }

    /// Only copies when the distance is inside the history (an invalid match
    /// is encoded all the same, just not remembered).
    fn copyHist(e: *SymEnc, dist: u32, len: u32) !void {
        if (dist >= e.hist.items.len) return;
        for (0..len) |_| try e.hist.append(gpa, e.hist.items[e.hist.items.len - dist - 1]);
    }

    fn distSlot(d: u32) u32 {
        if (d < 4) return d;
        const n: u32 = 31 - @clz(d);
        return 2 * n + ((d >> @intCast(n - 1)) & 1);
    }

    /// A match with a new distance (`rep0`, zero based). `0xFFFF_FFFF` is the end marker.
    fn match(e: *SymEnc, rep0: u32, len: u32) !void {
        const ps_ = e.ps();
        e.rc.bit(&e.p.is_match[e.st][ps_], 1);
        e.rc.bit(&e.p.is_rep[e.st], 0);
        e.st = c.updateMatch(e.st);
        const old = e.rep; // not `e.rep = .{ .. e.rep[0] .. }`: the literal is built in place
        e.rep = .{ rep0, old[0], old[1], old[2] };
        e.encLen(&e.p.match_len, len, ps_);
        const slot = distSlot(rep0);
        e.rc.bittree(&e.p.dist_slot[c.distState(len)], 6, slot);
        if (slot >= 4) {
            const footer: u5 = @intCast((slot >> 1) - 1);
            const base: u32 = (2 | (slot & 1)) << footer;
            const reduced = rep0 - base;
            if (slot < 14) {
                e.rc.bittreeReverseAt(&e.p.pos_special, base - slot, footer, reduced);
            } else {
                e.rc.direct(reduced >> 4, footer - 4);
                e.rc.bittreeReverse(&e.p.pos_align, 4, reduced & 15);
            }
        }
        try e.copyHist(rep0, len);
        try e.drain();
    }

    fn eopm(e: *SymEnc) !void {
        try e.match(0xFFFF_FFFF, 2);
    }

    fn shortRep(e: *SymEnc) !void {
        const ps_ = e.ps();
        e.rc.bit(&e.p.is_match[e.st][ps_], 1);
        e.rc.bit(&e.p.is_rep[e.st], 1);
        e.rc.bit(&e.p.is_rep0[e.st], 0);
        e.rc.bit(&e.p.is_rep0_long[e.st][ps_], 0);
        e.st = c.updateShortRep(e.st);
        try e.copyHist(e.rep[0], 1);
        try e.drain();
    }

    fn longRep(e: *SymEnc, idx: u2, len: u32) !void {
        const ps_ = e.ps();
        e.rc.bit(&e.p.is_match[e.st][ps_], 1);
        e.rc.bit(&e.p.is_rep[e.st], 1);
        if (idx == 0) {
            e.rc.bit(&e.p.is_rep0[e.st], 0);
            e.rc.bit(&e.p.is_rep0_long[e.st][ps_], 1);
        } else {
            e.rc.bit(&e.p.is_rep0[e.st], 1);
            if (idx == 1) {
                e.rc.bit(&e.p.is_rep1[e.st], 0);
            } else {
                e.rc.bit(&e.p.is_rep1[e.st], 1);
                e.rc.bit(&e.p.is_rep2[e.st], if (idx == 2) 0 else 1);
            }
            const d = e.rep[idx];
            if (idx == 3) e.rep[3] = e.rep[2];
            if (idx >= 2) e.rep[2] = e.rep[1];
            e.rep[1] = e.rep[0];
            e.rep[0] = d;
        }
        e.st = c.updateLongRep(e.st);
        e.encLen(&e.p.rep_len, len, ps_);
        try e.copyHist(e.rep[0], len);
        try e.drain();
    }

    /// Stored (uncompressed) LZMA2 data: only the history grows.
    fn stored(e: *SymEnc, bytes: []const u8) !void {
        try e.hist.appendSlice(gpa, bytes);
    }

    /// Flush the range coder; the bytes of the run so far (owned by the caller).
    fn endRun(e: *SymEnc) ![]u8 {
        e.rc.flush();
        try e.drain();
        const s = try gpa.dupe(u8, e.out.items);
        e.out.clearRetainingCapacity();
        return s;
    }
};

fn lzma1(lc: u8, lp: u8, pb: u8, dict: u32, size: ?u64, allow_eopm: bool) lzma.Format {
    return .{ .lzma1 = .{ .props = .{ .lc = lc, .lp = lp, .pb = pb, .dict_size = dict }, .uncompressed_size = size, .allow_eopm = allow_eopm } };
}

fn withTail(a: []const u8, tail_len: usize) ![]u8 {
    const r = try gpa.alloc(u8, a.len + tail_len);
    @memcpy(r[0..a.len], a);
    @memset(r[a.len..], 0xA5);
    return r;
}

// ── a reader that hands out `chunk` bytes at a time through a tiny buffer ───

const Dribble = struct {
    data: []const u8,
    pos: usize = 0,
    chunk: usize,
    reader: Reader,

    fn init(data: []const u8, chunk: usize, buffer: []u8) Dribble {
        return .{ .data = data, .chunk = chunk, .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 } };
    }

    fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const self: *Dribble = @alignCast(@fieldParentPtr("reader", r));
        if (self.pos >= self.data.len) return error.EndOfStream;
        const n = limit.minInt(@min(self.chunk, self.data.len - self.pos));
        try w.writeAll(self.data[self.pos..][0..n]);
        self.pos += n;
        return n;
    }
};

fn readAllChunked(d: *lzma.Decoder, list: *std.ArrayList(u8), chunk: usize) !void {
    var buf: [256]u8 = undefined;
    while (true) {
        const n = try d.read(buf[0..chunk]);
        if (n == 0) return;
        try list.appendSlice(gpa, buf[0..n]);
    }
}

// ── LZMA2 and .xz byte builders ─────────────────────────────────────────────

/// ctl is 0x80 | reset bits (0x00 none, 0x20 state, 0x40 props, 0x60 all).
fn appendChunk(list: *std.ArrayList(u8), ctl: u8, usize_: u32, csize_delta: i32, props: ?u8, rc: []const u8) !void {
    const u = usize_ - 1;
    const cs: u32 = @intCast(@as(i64, @intCast(rc.len)) + csize_delta - 1);
    try list.appendSlice(gpa, &.{ ctl | @as(u8, @intCast(u >> 16)), @intCast((u >> 8) & 0xFF), @intCast(u & 0xFF), @intCast(cs >> 8), @intCast(cs & 0xFF) });
    if (props) |p| try list.append(gpa, p);
    try list.appendSlice(gpa, rc);
}

fn appendStored(list: *std.ArrayList(u8), ctl: u8, bytes: []const u8) !void {
    try list.appendSlice(gpa, &.{ ctl, @intCast((bytes.len - 1) >> 8), @intCast((bytes.len - 1) & 0xFF) });
    try list.appendSlice(gpa, bytes);
}

fn propsByte(lc: u8, lp: u8, pb: u8) u8 {
    return (c.Lclppb{ .lc = lc, .lp = lp, .pb = pb }).encode();
}

fn vliBytes(list: *std.ArrayList(u8), v_in: u64) !void {
    var v = v_in;
    while (v >= 0x80) : (v >>= 7) try list.append(gpa, @as(u8, @intCast(v & 0x7F)) | 0x80);
    try list.append(gpa, @intCast(v));
}

fn padTo4(list: *std.ArrayList(u8), start: usize, byte: u8) !void {
    while ((list.items.len - start) % 4 != 0) try list.append(gpa, byte);
}

fn appendCrc32(list: *std.ArrayList(u8), from: usize) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, std.hash.Crc32.hash(list.items[from..]), .little);
    try list.appendSlice(gpa, &b);
}

const XzSpec = struct {
    /// Raw LZMA2 chunks, the 0x00 end byte included.
    payload: []const u8,
    /// The real uncompressed size (what the index must say).
    unc: u64,
    check: xzfmt.Check = .none,
    check_bytes: []const u8 = &.{},
    hdr_unc: ?u64 = null,
    hdr_comp: ?u64 = null,
    dict_byte: u8 = 0,
    block_pad_byte: u8 = 0,
    idx_count_raw: ?[]const u8 = null,
    idx_unpadded_delta: u64 = 0,
    idx_unc_delta: u64 = 0,
    idx_swap: bool = false,
    idx_pad_byte: u8 = 0,
    idx_crc_xor: u32 = 0,
    footer_backward_add: u32 = 0,
    footer_check: ?xzfmt.Check = null,
};

fn buildXz(s: XzSpec) ![]u8 {
    var o: std.ArrayList(u8) = .empty;
    errdefer o.deinit(gpa);
    // Stream header.
    try o.appendSlice(gpa, &xzfmt.header_magic);
    const fl = o.items.len;
    try o.appendSlice(gpa, &.{ 0, @backingInt(s.check) });
    var crc: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc, std.hash.Crc32.hash(o.items[fl..]), .little);
    try o.appendSlice(gpa, &crc);
    // Block header.
    const bh = o.items.len;
    try o.appendSlice(gpa, &.{ 0, (if (s.hdr_comp != null) @as(u8, 0x40) else 0) | (if (s.hdr_unc != null) @as(u8, 0x80) else 0) });
    if (s.hdr_comp) |v| try vliBytes(&o, v);
    if (s.hdr_unc) |v| try vliBytes(&o, v);
    try o.appendSlice(gpa, &.{ 0x21, 0x01, s.dict_byte });
    while ((o.items.len - bh + 4) % 4 != 0) try o.append(gpa, 0);
    const hsize = o.items.len - bh + 4;
    o.items[bh] = @intCast(hsize / 4 - 1);
    try appendCrc32(&o, bh);
    // Block data, padding, check.
    const body = o.items.len;
    try o.appendSlice(gpa, s.payload);
    try padTo4(&o, body, s.block_pad_byte);
    try o.appendSlice(gpa, s.check_bytes);
    const unpadded: u64 = hsize + s.payload.len + xzfmt.checkSize(s.check);
    // Index.
    const ix = o.items.len;
    try o.append(gpa, 0);
    if (s.idx_count_raw) |raw| try o.appendSlice(gpa, raw) else try vliBytes(&o, 1);
    const a_val = unpadded + s.idx_unpadded_delta;
    const b_val = s.unc + s.idx_unc_delta;
    try vliBytes(&o, if (s.idx_swap) b_val else a_val);
    try vliBytes(&o, if (s.idx_swap) a_val else b_val);
    try padTo4(&o, ix, s.idx_pad_byte);
    var ic: [4]u8 = undefined;
    std.mem.writeInt(u32, &ic, std.hash.Crc32.hash(o.items[ix..]) ^ s.idx_crc_xor, .little);
    try o.appendSlice(gpa, &ic);
    const idx_len = o.items.len - ix;
    // Footer.
    const ft = o.items.len;
    var back: [4]u8 = undefined;
    std.mem.writeInt(u32, &back, @intCast(idx_len / 4 - 1 + s.footer_backward_add), .little);
    try o.appendSlice(gpa, &back);
    try o.appendSlice(gpa, &.{ 0, @backingInt(s.footer_check orelse s.check) });
    var fc: [4]u8 = undefined;
    std.mem.writeInt(u32, &fc, std.hash.Crc32.hash(o.items[ft..]), .little);
    try o.insertSlice(gpa, ft, &fc);
    try o.appendSlice(gpa, &xzfmt.footer_magic);
    return o.toOwnedSlice(gpa);
}

fn storedPayload(bytes: []const u8) ![]u8 {
    var p: std.ArrayList(u8) = .empty;
    errdefer p.deinit(gpa);
    try appendStored(&p, 1, bytes);
    try p.append(gpa, 0);
    return p.toOwnedSlice(gpa);
}

fn expectDecodes(want: []const u8, input: []const u8, f: lzma.Format, opts: lzma.DecodeOptions) !void {
    const got = try lzma.decompress(gpa, input, f, opts);
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, want, got);
}

// ── tests ───────────────────────────────────────────────────────────────────

fn randomStream(e: *SymEnc, rnd: std.Random, n_syms: usize, win: usize, mask: u4) !void {
    try e.literal(rnd.int(u8));
    for (0..n_syms) |_| {
        const full: u32 = @intCast(@min(e.hist.items.len, win));
        var k = rnd.uintLessThan(u32, 100);
        if (k >= 35 and k < 60 and mask & 1 == 0) k = 0;
        if (k >= 60 and k < 72 and mask & 2 == 0) k = 0;
        if (k >= 72 and mask & 4 == 0) k = 0;
        if (k < 35) {
            const b = if (rnd.boolean()) e.hist.items[rnd.uintLessThan(usize, e.hist.items.len)] else rnd.int(u8);
            try e.literal(b);
        } else if (k < 60) {
            const far = rnd.uintLessThan(u32, 4) == 0;
            const rep0 = rnd.uintLessThan(u32, if (far) full else @min(full, 40));
            const len = 2 + (if (rnd.boolean()) rnd.uintLessThan(u32, 8) else rnd.uintLessThan(u32, 272));
            try e.match(rep0, len);
        } else if (k < 72) {
            try e.shortRep();
        } else {
            try e.longRep(@intCast(rnd.uintLessThan(u32, 4)), 2 + (if (rnd.boolean()) rnd.uintLessThan(u32, 17) else rnd.uintLessThan(u32, 272)));
        }
    }
}

test "symbol streams: every symbol kind, random lc/lp/pb and dictionaries, fast and slow input paths" {
    const Case = struct { lc: u5, lp: u5, pb: u5, dict: u32, win: usize };
    const cases = [_]Case{
        .{ .lc = 3, .lp = 0, .pb = 2, .dict = 4096, .win = 4096 },
        .{ .lc = 0, .lp = 4, .pb = 4, .dict = 4100, .win = 4112 },
        .{ .lc = 4, .lp = 0, .pb = 0, .dict = 5000, .win = 5008 },
        .{ .lc = 2, .lp = 2, .pb = 3, .dict = 4096, .win = 4096 },
        .{ .lc = 1, .lp = 3, .pb = 1, .dict = 100, .win = 4096 },
    };
    for (cases, 0..) |cs, ci| {
        var prng: std.Random.DefaultPrng = .init(0x5EED + ci);
        var e = try SymEnc.init(cs.lc, cs.lp, cs.pb);
        defer e.deinit();
        try randomStream(&e, prng.random(), 1500, cs.win, 7);
        try e.eopm();
        const z = try e.endRun();
        defer gpa.free(z);
        try testing.expect(e.hist.items.len > 3 * cs.win);
        const f = lzma1(cs.lc, cs.lp, cs.pb, cs.dict, null, true);
        try expectDecodes(e.hist.items, z, f, .{});
        // With a tail, so that the end marker is met on the fast path.
        const zt = try withTail(z, 64);
        defer gpa.free(zt);
        try expectDecodes(e.hist.items, zt, f, .{});
        // Streamed through a reader that hands out a few bytes at a time.
        for ([_]usize{ 1, 5, 24, 200 }) |chunk| {
            var rb: [8]u8 = undefined;
            var dr = Dribble.init(zt, chunk, &rb);
            var d = try lzma.Decoder.init(gpa, &dr.reader, f, .{});
            defer d.deinit();
            var got: std.ArrayList(u8) = .empty;
            defer got.deinit(gpa);
            try readAllChunked(&d, &got, 100);
            try testing.expectEqualSlices(u8, e.hist.items, got.items);
        }
    }
}

test "symbol streams: a match one byte too far back is CorruptData, in front of a long tail too" {
    var e = try SymEnc.init(3, 0, 2);
    defer e.deinit();
    for ("abcd") |ch| try e.literal(ch);
    try e.match(3, 2);
    try e.eopm();
    const ok = try e.endRun();
    defer gpa.free(ok);
    const f = lzma1(3, 0, 2, 1 << 16, null, true);
    try expectDecodes("abcdab", ok, f, .{});

    var bad = try SymEnc.init(3, 0, 2);
    defer bad.deinit();
    for ("abcd") |ch| try bad.literal(ch);
    try bad.match(4, 2); // 5 bytes back, 4 written
    try bad.eopm();
    const z = try bad.endRun();
    defer gpa.free(z);
    const zt = try withTail(z, 64);
    defer gpa.free(zt);
    try testing.expectError(error.CorruptData, lzma.decompress(gpa, z, f, .{}));
    try testing.expectError(error.CorruptData, lzma.decompress(gpa, zt, f, .{}));
}

test "symbol streams: the window is the rounded dictionary size, distance win - 1 works, win does not" {
    var prng: std.Random.DefaultPrng = .init(77);
    const f = lzma1(3, 0, 2, 4096, null, true);
    for ([_]u32{ 4095, 4096 }) |dist| {
        var e = try SymEnc.init(3, 0, 2);
        defer e.deinit();
        for (0..5000) |_| try e.literal(prng.random().int(u8));
        try e.match(dist, 3);
        try e.eopm();
        const z = try e.endRun();
        defer gpa.free(z);
        const zt = try withTail(z, 64);
        defer gpa.free(zt);
        if (dist == 4095) {
            try expectDecodes(e.hist.items, z, f, .{});
            try expectDecodes(e.hist.items, zt, f, .{});
        } else {
            try testing.expectError(error.CorruptData, lzma.decompress(gpa, z, f, .{}));
            try testing.expectError(error.CorruptData, lzma.decompress(gpa, zt, f, .{}));
        }
    }
    // A header dictionary below 4096 is raised to 4096.
    var e = try SymEnc.init(3, 0, 2);
    defer e.deinit();
    for (0..3100) |_| try e.literal(prng.random().int(u8));
    try e.match(3000, 4);
    try e.eopm();
    const z = try e.endRun();
    defer gpa.free(z);
    try expectDecodes(e.hist.items, z, lzma1(3, 0, 2, 1, null, true), .{});
}

test "symbol streams: lc + lp = 4 and pb = 4 are valid, lc + lp = 5 and pb = 5 are BadHeader" {
    for ([_][3]u8{ .{ 4, 0, 4 }, .{ 0, 4, 0 } }) |p| {
        var e = try SymEnc.init(@intCast(p[0]), @intCast(p[1]), @intCast(p[2]));
        defer e.deinit();
        for ("hello") |ch| try e.literal(ch);
        const z = try e.endRun();
        defer gpa.free(z);
        try expectDecodes("hello", z, lzma1(p[0], p[1], p[2], 4096, 5, true), .{});
    }
    const z = [_]u8{ 0, 0, 0, 0, 0 };
    try testing.expectError(error.BadHeader, lzma.decompress(gpa, &z, lzma1(1, 4, 0, 4096, 0, true), .{}));
    try testing.expectError(error.BadHeader, lzma.decompress(gpa, &z, lzma1(0, 0, 5, 4096, 0, true), .{}));
    // The header form: toBytes accepts exactly what fromBytes does.
    const ok = lzma.Lzma1Props{ .lc = 0, .lp = 4, .pb = 4, .dict_size = 4096 };
    _ = try lzma.Lzma1Props.fromBytes(&ok.toBytes());
}

test "symbol streams: the end marker policy and the declared size" {
    var e = try SymEnc.init(3, 0, 2);
    defer e.deinit();
    for ("abc") |ch| try e.literal(ch);
    try e.eopm();
    const z = try e.endRun();
    defer gpa.free(z);
    // Known size and the marker allowed: fine. Not allowed: refused.
    try expectDecodes("abc", z, lzma1(3, 0, 2, 4096, 3, true), .{});
    try testing.expectError(error.CorruptData, lzma.decompress(gpa, z, lzma1(3, 0, 2, 4096, 3, false), .{}));
    // Unknown size needs the marker to be allowed.
    try expectDecodes("abc", z, lzma1(3, 0, 2, 4096, null, true), .{});
    try testing.expectError(error.CorruptData, lzma.decompress(gpa, z, lzma1(3, 0, 2, 4096, null, false), .{}));
    // A marker before the declared size is reached.
    try testing.expectError(error.CorruptData, lzma.decompress(gpa, z, lzma1(3, 0, 2, 4096, 10, true), .{}));
    // The marker, then a tail the fast path sees: the stream still ends at the marker.
    const zt = try withTail(z, 64);
    defer gpa.free(zt);
    try expectDecodes("abc", zt, lzma1(3, 0, 2, 4096, null, true), .{});
    // A flipped last byte is not a clean end.
    var bad = try gpa.dupe(u8, z);
    defer gpa.free(bad);
    bad[bad.len - 1] ^= 0x01;
    try expectAnyError(lzma.decompress(gpa, bad, lzma1(3, 0, 2, 4096, null, true), .{}));
    try expectAnyError(lzma.decompress(gpa, bad, lzma1(3, 0, 2, 4096, 3, true), .{}));
    // Known size, no marker, flipped last byte.
    var e2 = try SymEnc.init(3, 0, 2);
    defer e2.deinit();
    for ("abcdefgh") |ch| try e2.literal(ch);
    const z2 = try e2.endRun();
    defer gpa.free(z2);
    try expectDecodes("abcdefgh", z2, lzma1(3, 0, 2, 4096, 8, true), .{});
    z2[z2.len - 1] ^= 0x01;
    try expectAnyError(lzma.decompress(gpa, z2, lzma1(3, 0, 2, 4096, 8, true), .{}));
}

test "symbol streams: a symbol after the declared size is CorruptData, never a write past the ring" {
    inline for (.{ 0, 1, 2 }) |kind| {
        var e = try SymEnc.init(3, 0, 2);
        defer e.deinit();
        for ("abcde") |ch| try e.literal(ch);
        switch (kind) {
            0 => try e.literal('x'),
            1 => try e.shortRep(),
            else => try e.match(1, 3),
        }
        const z = try e.endRun();
        defer gpa.free(z);
        const zt = try withTail(z, 64);
        defer gpa.free(zt);
        try testing.expectError(error.CorruptData, lzma.decompress(gpa, z, lzma1(3, 0, 2, 4096, 5, true), .{}));
        try testing.expectError(error.CorruptData, lzma.decompress(gpa, zt, lzma1(3, 0, 2, 4096, 5, true), .{}));
    }
}

test "symbol streams: the decisions at the edge of the range coder (code == bound, code == range)" {
    // The last 1 bit of a stream always leaves code == bound; here it is an is_rep bit (a short repeat last).
    var e = try SymEnc.init(3, 0, 2);
    defer e.deinit();
    for ("abcdef") |ch| try e.literal(ch);
    try e.shortRep();
    const z = try e.endRun();
    defer gpa.free(z);
    try expectDecodes(e.hist.items, z, lzma1(3, 0, 2, 4096, 7, true), .{});
    // The last 1 bit is a direct bit: a distance whose bits end in 1 and four zero align bits.
    var prng: std.Random.DefaultPrng = .init(5);
    var e2 = try SymEnc.init(3, 0, 2);
    defer e2.deinit();
    for (0..400) |_| try e2.literal(prng.random().int(u8));
    try e2.match(0x110, 2);
    const z2 = try e2.endRun();
    defer gpa.free(z2);
    try expectDecodes(e2.hist.items, z2, lzma1(3, 0, 2, 4096, 402, true), .{});
    // And the same with a tail, on the fast path.
    const z2t = try withTail(z2, 64);
    defer gpa.free(z2t);
    try expectDecodes(e2.hist.items, z2t, lzma1(3, 0, 2, 4096, 402, true), .{});
}

test "symbol streams: an 8-byte-chunk copy of a period of 7 and of 8, wrapped sources, long runs" {
    for ([_]usize{ 6, 7, 8, 9 }) |period| {
        var e = try SymEnc.init(3, 0, 2);
        defer e.deinit();
        for (0..period) |i| try e.literal(@intCast('a' + i));
        try e.match(@intCast(period - 1), 60);
        try e.match(@intCast(period - 1), 273);
        try e.shortRep();
        try e.eopm();
        const z = try e.endRun();
        defer gpa.free(z);
        try expectDecodes(e.hist.items, z, lzma1(3, 0, 2, 4096, null, true), .{});
    }
}

test "symbol streams: lzma_alone and lzma1 trailing data" {
    const z = try lzma.compress(gpa, "hello hello hello", .lzma_alone, .{});
    defer gpa.free(z);
    const zt = try withTail(z, 1);
    defer gpa.free(zt);
    try expectDecodes("hello hello hello", z, .lzma_alone, .{});
    try testing.expectError(error.TrailingData, lzma.decompress(gpa, zt, .lzma_alone, .{}));
    try expectDecodes("hello hello hello", zt, .lzma_alone, .{ .ignore_trailing_garbage = true });
    // The same stream as raw LZMA1: what follows is not looked at.
    var e = try SymEnc.init(3, 0, 2);
    defer e.deinit();
    for ("abc") |ch| try e.literal(ch);
    const r = try e.endRun();
    defer gpa.free(r);
    const rt = try withTail(r, 1);
    defer gpa.free(rt);
    try expectDecodes("abc", rt, lzma1(3, 0, 2, 4096, 3, true), .{});
}

test "setupDict: the caps (max_output small with a huge dictionary, max_dict exact, a ring of another size)" {
    const stored = [_]u8{ 1, 0, 9 } ++ ("0123456789".*) ++ [_]u8{0};
    // The ring is capped by max_output + 1 before it is compared with max_dict.
    try expectDecodes("0123456789", &stored, .{ .lzma2 = .{ .dict_size = 1 << 30 } }, .{ .max_output = 100 });
    // max_dict itself is allowed, one more is not.
    try expectDecodes("0123456789", &stored, .{ .lzma2 = .{ .dict_size = 1 << 16 } }, .{ .max_dict = 1 << 16, .max_output = null });
    try testing.expectError(error.DictTooLarge, lzma.decompress(gpa, &stored, .{ .lzma2 = .{ .dict_size = (1 << 16) + 16 } }, .{ .max_dict = 1 << 16, .max_output = null }));
    // Two streams with different dictionaries: the second needs a longer ring than the first.
    var prng: std.Random.DefaultPrng = .init(11);
    var unit: [6000]u8 = undefined;
    prng.random().bytes(&unit);
    const plain2 = try std.mem.concat(gpa, u8, &.{ &unit, &unit });
    defer gpa.free(plain2);
    var o1 = lzma.preset(1, false);
    o1.dict_size = 4096;
    var o2 = lzma.preset(1, false);
    o2.dict_size = 1 << 16;
    const s1 = try lzma.compress(gpa, "abc", .xz, .{ .lzma = o1 });
    defer gpa.free(s1);
    const s2 = try lzma.compress(gpa, plain2, .xz, .{ .lzma = o2 });
    defer gpa.free(s2);
    const both = try std.mem.concat(gpa, u8, &.{ s1, s2 });
    defer gpa.free(both);
    const want = try std.mem.concat(gpa, u8, &.{ "abc", plain2 });
    defer gpa.free(want);
    try expectDecodes(want, both, .xz, .{});
    // And the other way round (a ring that shrinks).
    const both2 = try std.mem.concat(gpa, u8, &.{ s2, s1 });
    defer gpa.free(both2);
    const want2 = try std.mem.concat(gpa, u8, &.{ plain2, "abc" });
    defer gpa.free(want2);
    try expectDecodes(want2, both2, .xz, .{});
}

fn expectAnyError(r: anyerror![]u8) !void {
    if (r) |ok| {
        gpa.free(ok);
        return error.ExpectedAnError;
    } else |_| {}
}

fn lzma2Run(f: lzma.Format, input: []const u8) lzma.DecodeError![]u8 {
    return lzma.decompress(gpa, input, f, .{});
}

test "lzma2 chunks: dictionary and state resets, property changes, stored chunks in between" {
    const f: lzma.Format = .{ .lzma2 = .{ .dict_size = 4096 } };
    var prng: std.Random.DefaultPrng = .init(21);
    // 1. E0, stored (ctl 2, nothing reset), 80 (nothing reset): continues.
    {
        var e = try SymEnc.init(3, 0, 2);
        defer e.deinit();
        var s: std.ArrayList(u8) = .empty;
        defer s.deinit(gpa);
        for (0..60) |_| try e.literal(prng.random().int(u8));
        const r1 = try e.endRun();
        defer gpa.free(r1);
        try appendChunk(&s, 0xE0, 60, 0, propsByte(3, 0, 2), r1);
        try appendStored(&s, 2, "xyz");
        try e.stored("xyz");
        const n0 = e.hist.items.len;
        try e.match(10, 20);
        try e.literal('q');
        const r2 = try e.endRun();
        defer gpa.free(r2);
        try appendChunk(&s, 0x80, @intCast(e.hist.items.len - n0), 0, null, r2);
        try s.append(gpa, 0);
        try expectDecodes(e.hist.items, s.items, f, .{});
        // 2. The same with a stored chunk that resets (ctl 1): an 80 chunk may not follow.
        var s2: std.ArrayList(u8) = .empty;
        defer s2.deinit(gpa);
        try appendChunk(&s2, 0xE0, 60, 0, propsByte(3, 0, 2), r1);
        try appendStored(&s2, 1, "xyz");
        try appendChunk(&s2, 0x80, 21, 0, null, r2);
        try s2.append(gpa, 0);
        try testing.expectError(error.CorruptData, lzma2Run(f, s2.items));
    }
    // 3. A dictionary reset in the middle hides what came before (after a wrap, too).
    for ([_]bool{ false, true }) |inval| {
        var e = try SymEnc.init(3, 0, 2);
        defer e.deinit();
        var s: std.ArrayList(u8) = .empty;
        defer s.deinit(gpa);
        for (0..5000) |_| try e.literal(prng.random().int(u8));
        const r1 = try e.endRun();
        defer gpa.free(r1);
        try appendChunk(&s, 0xE0, 5000, 0, propsByte(3, 0, 2), r1);
        var e2 = try SymEnc.init(3, 0, 2);
        defer e2.deinit();
        try e2.literal('z');
        try e2.match(if (inval) 2 else 0, 3);
        const r2 = try e2.endRun();
        defer gpa.free(r2);
        try appendChunk(&s, 0xE0, 4, 0, propsByte(3, 0, 2), r2);
        try s.append(gpa, 0);
        if (inval) {
            try testing.expectError(error.CorruptData, lzma2Run(f, s.items));
        } else {
            const want = try std.mem.concat(gpa, u8, &.{ e.hist.items, e2.hist.items });
            defer gpa.free(want);
            try expectDecodes(want, s.items, f, .{});
        }
    }
    // 4. After a stored chunk with a reset, an LZMA chunk with new properties: sees only the stored bytes.
    for ([_]bool{ false, true }) |inval| {
        var s: std.ArrayList(u8) = .empty;
        defer s.deinit(gpa);
        var e1 = try SymEnc.init(3, 0, 2);
        defer e1.deinit();
        for ("abcd") |ch| try e1.literal(ch);
        const r1 = try e1.endRun();
        defer gpa.free(r1);
        try appendChunk(&s, 0xE0, 4, 0, propsByte(3, 0, 2), r1);
        try appendStored(&s, 1, "x");
        var e = try SymEnc.init(0, 2, 1); // different lc/lp/pb
        defer e.deinit();
        try e.stored("x");
        try e.match(if (inval) 1 else 0, 4);
        if (!inval) try e.literal('k');
        const r = try e.endRun();
        defer gpa.free(r);
        try appendChunk(&s, 0xC0, 5, 0, propsByte(0, 2, 1), r);
        // A further chunk without properties must now be accepted (props are known).
        try e.shortRep();
        const r3 = try e.endRun();
        defer gpa.free(r3);
        try appendChunk(&s, 0x80, 1, 0, null, r3);
        try s.append(gpa, 0);
        if (inval) {
            try testing.expectError(error.CorruptData, lzma2Run(f, s.items));
        } else {
            const want = try std.mem.concat(gpa, u8, &.{ e1.hist.items, e.hist.items });
            defer gpa.free(want);
            try expectDecodes(want, s.items, f, .{});
        }
    }
    // 5. State reset without a dictionary reset (A0): the second run is encoded from a fresh model.
    {
        var e = try SymEnc.init(3, 0, 2);
        defer e.deinit();
        var s: std.ArrayList(u8) = .empty;
        defer s.deinit(gpa);
        for (0..80) |_| try e.literal(prng.random().int(u8));
        const r1 = try e.endRun();
        defer gpa.free(r1);
        try appendChunk(&s, 0xE0, 80, 0, propsByte(3, 0, 2), r1);
        e.resetModel();
        const n0 = e.hist.items.len;
        for (0..40) |_| try e.literal(prng.random().int(u8));
        try e.match(70, 30);
        const r2 = try e.endRun();
        defer gpa.free(r2);
        try appendChunk(&s, 0xA0, @intCast(e.hist.items.len - n0), 0, null, r2);
        try s.append(gpa, 0);
        try expectDecodes(e.hist.items, s.items, f, .{});
    }
    // 6. Control bytes 3.. are reserved, also after a first chunk.
    try testing.expectError(error.CorruptData, lzma2Run(f, &.{ 1, 0, 0, 'a', 3, 0, 0, 'b', 0 }));
    // 7. A chunk of more than 65536 bytes (the high bits of the control byte).
    {
        var e = try SymEnc.init(3, 0, 2);
        defer e.deinit();
        try e.literal('a');
        while (e.hist.items.len + 273 <= 70_000) try e.match(0, 273);
        while (e.hist.items.len < 70_000) try e.shortRep();
        var s: std.ArrayList(u8) = .empty;
        defer s.deinit(gpa);
        const r = try e.endRun();
        defer gpa.free(r);
        try appendChunk(&s, 0xE0, 70_000, 0, propsByte(3, 0, 2), r);
        try s.append(gpa, 0);
        try expectDecodes(e.hist.items, s.items, f, .{});
    }
}

test "lzma2 chunks: sizes must agree with the data, a short chunk never reads on into the next one" {
    const f: lzma.Format = .{ .lzma2 = .{ .dict_size = 4096 } };
    var prng: std.Random.DefaultPrng = .init(31);
    var e = try SymEnc.init(3, 0, 2);
    defer e.deinit();
    for (0..300) |_| try e.literal(prng.random().int(u8));
    const r = try e.endRun();
    defer gpa.free(r);
    const p = propsByte(3, 0, 2);
    var s: std.ArrayList(u8) = .empty;
    defer s.deinit(gpa);
    try appendChunk(&s, 0xE0, 300, 0, p, r);
    try s.append(gpa, 0);
    try expectDecodes(e.hist.items, s.items, f, .{});
    // A compressed size one too large (the byte after the data is eaten), and one too small, with plenty after it.
    var too_big: std.ArrayList(u8) = .empty;
    defer too_big.deinit(gpa);
    try appendChunk(&too_big, 0xE0, 300, 1, p, r);
    try too_big.appendSlice(gpa, &.{ 0, 0 });
    try testing.expectError(error.CorruptData, lzma2Run(f, too_big.items));
    var too_small: std.ArrayList(u8) = .empty;
    defer too_small.deinit(gpa);
    try appendChunk(&too_small, 0xE0, 300, -10, p, r);
    try too_small.appendSlice(gpa, r[r.len - 10 ..]);
    try too_small.append(gpa, 0);
    const pad = try withTail(too_small.items, 64);
    defer gpa.free(pad);
    try testing.expectError(error.CorruptData, lzma2Run(f, pad));
    // A flipped last byte of the run is not a clean end.
    const bad = try gpa.dupe(u8, s.items);
    defer gpa.free(bad);
    bad[bad.len - 2] ^= 1;
    try expectAnyError(lzma2Run(f, bad));
    // The first range coder byte is zero.
    const bad0 = try gpa.dupe(u8, s.items);
    defer gpa.free(bad0);
    bad0[6] = 1;
    try testing.expectError(error.CorruptData, lzma2Run(f, bad0));
    // Fewer than five bytes in the chunk: the budget runs out inside the initial read.
    try testing.expectError(error.CorruptData, lzma2Run(f, &.{ 0xE0, 0, 0, 0, 0, 0x5D, 0, 0 }));
    // A match that runs past the declared size leaves bytes pending.
    var e2 = try SymEnc.init(3, 0, 2);
    defer e2.deinit();
    try e2.literal('a');
    try e2.match(0, 20);
    const r2 = try e2.endRun();
    defer gpa.free(r2);
    var sp: std.ArrayList(u8) = .empty;
    defer sp.deinit(gpa);
    try appendChunk(&sp, 0xE0, 10, 0, p, r2);
    try sp.append(gpa, 0);
    try testing.expectError(error.CorruptData, lzma2Run(f, sp.items));
    // The same through a known-size LZMA1 stream.
    try testing.expectError(error.CorruptData, lzma.decompress(gpa, r2, lzma1(3, 0, 2, 4096, 10, true), .{}));
}

test "xz: hand-built streams, every padding alignment, then one bent field at a time" {
    // Alignment: payload sizes 1..8 give every block and index padding.
    for (1..9) |n| {
        var data: [8]u8 = undefined;
        for (data[0..n], 0..) |*b, i| b.* = @intCast('a' + i);
        const pl = try storedPayload(data[0..n]);
        defer gpa.free(pl);
        const z = try buildXz(.{ .payload = pl, .unc = n });
        defer gpa.free(z);
        try expectDecodes(data[0..n], z, .xz, .{});
    }
    const pl = try storedPayload("hello"); // payload 9 bytes: 3 bytes of block padding
    defer gpa.free(pl);
    const ok = try buildXz(.{ .payload = pl, .unc = 5 });
    defer gpa.free(ok);
    try expectDecodes("hello", ok, .xz, .{});
    const Bad = struct { spec: XzSpec, err: lzma.DecodeError };
    const raw10 = [_]u8{ 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 };
    const huge = [_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 };
    const nonmin = [_]u8{ 0x81, 0x00 };
    const bads = [_]Bad{
        .{ .spec = .{ .payload = pl, .unc = 5, .block_pad_byte = 1 }, .err = error.CorruptData },
        .{ .spec = .{ .payload = pl, .unc = 5, .idx_unc_delta = 1 }, .err = error.BadIndex },
        .{ .spec = .{ .payload = pl, .unc = 5, .idx_unpadded_delta = 4 }, .err = error.BadIndex },
        .{ .spec = .{ .payload = pl, .unc = 5, .idx_swap = true }, .err = error.BadIndex },
        .{ .spec = .{ .payload = pl, .unc = 5, .idx_count_raw = &huge }, .err = error.BadIndex },
        .{ .spec = .{ .payload = pl, .unc = 5, .idx_count_raw = &raw10 }, .err = error.BadIndex },
        .{ .spec = .{ .payload = pl, .unc = 5, .idx_count_raw = &nonmin }, .err = error.BadIndex },
        .{ .spec = .{ .payload = pl, .unc = 5, .idx_crc_xor = 1 }, .err = error.BadIndex },
        .{ .spec = .{ .payload = pl, .unc = 5, .footer_check = .crc32 }, .err = error.BadFooter },
        .{ .spec = .{ .payload = pl, .unc = 5, .footer_backward_add = 1 }, .err = error.BadFooter },
        .{ .spec = .{ .payload = pl, .unc = 5, .hdr_unc = 6 }, .err = error.CorruptData },
        .{ .spec = .{ .payload = pl, .unc = 5, .hdr_comp = 8 }, .err = error.CorruptData },
    };
    for (bads, 0..) |b, i| {
        const z = try buildXz(b.spec);
        defer gpa.free(z);
        testing.expectError(b.err, lzma.decompress(gpa, z, .xz, .{})) catch |e| {
            std.debug.print("xz bent field case {d}\n", .{i});
            return e;
        };
    }
    // Nonzero index padding: a 124-byte block needs a two-byte unpadded size, so the index has three bytes of padding.
    {
        var big: [120]u8 = undefined;
        @memset(&big, 'z');
        const plb = try storedPayload(&big);
        defer gpa.free(plb);
        const zok = try buildXz(.{ .payload = plb, .unc = 120 });
        defer gpa.free(zok);
        try expectDecodes(&big, zok, .xz, .{});
        const z = try buildXz(.{ .payload = plb, .unc = 120, .idx_pad_byte = 1 });
        defer gpa.free(z);
        try testing.expectError(error.BadIndex, lzma.decompress(gpa, z, .xz, .{}));
    }
    // Header sizes that are right are accepted; a dictionary property of 128 MiB is fine when the block is 5 bytes.
    {
        const z = try buildXz(.{ .payload = pl, .unc = 5, .hdr_unc = 5, .hdr_comp = pl.len, .dict_byte = 30 });
        defer gpa.free(z);
        try expectDecodes("hello", z, .xz, .{});
    }
    // The check fields: every byte of each is compared.
    const chk = [_]struct { k: xzfmt.Check, n: usize }{ .{ .k = .crc32, .n = 4 }, .{ .k = .crc64, .n = 8 }, .{ .k = .sha256, .n = 32 } };
    for (chk) |ck| {
        var good: [32]u8 = undefined;
        switch (ck.k) {
            .crc32 => std.mem.writeInt(u32, good[0..4], std.hash.Crc32.hash("hello"), .little),
            .crc64 => std.mem.writeInt(u64, good[0..8], std.hash.crc.@"CRC-64/XZ".hash("hello"), .little),
            else => std.crypto.hash.sha2.Sha256.hash("hello", good[0..32], .{}),
        }
        const z = try buildXz(.{ .payload = pl, .unc = 5, .check = ck.k, .check_bytes = good[0..ck.n] });
        defer gpa.free(z);
        try expectDecodes("hello", z, .xz, .{});
        for (0..ck.n) |i| {
            var badc = good;
            badc[i] ^= 0x80;
            const zb = try buildXz(.{ .payload = pl, .unc = 5, .check = ck.k, .check_bytes = badc[0..ck.n] });
            defer gpa.free(zb);
            try testing.expectError(error.CheckMismatch, lzma.decompress(gpa, zb, .xz, .{}));
        }
    }
}

test "xz: what follows a stream, stream padding, a second stream that starts without a dictionary reset" {
    const a = try lzma.compress(gpa, "first ", .xz, .{});
    defer gpa.free(a);
    const b = try lzma.compress(gpa, "second", .xz, .{});
    defer gpa.free(b);
    const junk = try std.mem.concat(gpa, u8, &.{ a, "abc" });
    defer gpa.free(junk);
    try testing.expectError(error.TrailingData, lzma.decompress(gpa, junk, .xz, .{}));
    try expectDecodes("first ", junk, .xz, .{ .ignore_trailing_garbage = true });
    const half = try std.mem.concat(gpa, u8, &.{ a, &.{ 0xFD, 0x37 } });
    defer gpa.free(half);
    try testing.expectError(error.TrailingData, lzma.decompress(gpa, half, .xz, .{}));
    const wrongmagic = try std.mem.concat(gpa, u8, &.{ a, &.{ 0xFD, 0x37, 0x7a, 0x58, 0x5a, 0x01 } });
    defer gpa.free(wrongmagic);
    try testing.expectError(error.TrailingData, lzma.decompress(gpa, wrongmagic, .xz, .{}));
    // Two bytes of stream padding between streams are not a multiple of four.
    const odd = try std.mem.concat(gpa, u8, &.{ a, &.{ 0, 0 }, b });
    defer gpa.free(odd);
    try testing.expectError(error.BadFooter, lzma.decompress(gpa, odd, .xz, .{}));
    // Second stream: a block whose first chunk is 0x80 (continuing) after a block that set everything.
    var e = try SymEnc.init(3, 0, 2);
    defer e.deinit();
    var p1: std.ArrayList(u8) = .empty;
    defer p1.deinit(gpa);
    for ("ab") |ch| try e.literal(ch);
    const r1 = try e.endRun();
    defer gpa.free(r1);
    try appendChunk(&p1, 0xE0, 2, 0, propsByte(3, 0, 2), r1);
    try p1.append(gpa, 0);
    for ("cd") |ch| try e.literal(ch);
    const r2 = try e.endRun();
    defer gpa.free(r2);
    var p2: std.ArrayList(u8) = .empty;
    defer p2.deinit(gpa);
    try appendChunk(&p2, 0x80, 2, 0, null, r2);
    try p2.append(gpa, 0);
    const s1 = try buildXz(.{ .payload = p1.items, .unc = 2 });
    defer gpa.free(s1);
    const s2 = try buildXz(.{ .payload = p2.items, .unc = 2 });
    defer gpa.free(s2);
    const both = try std.mem.concat(gpa, u8, &.{ s1, s2 });
    defer gpa.free(both);
    try testing.expectError(error.CorruptData, lzma.decompress(gpa, both, .xz, .{}));
    // A block that declares no output after a block that had some (the ring shrinks to nothing).
    const empty_payload = [_]u8{0};
    const s3 = try buildXz(.{ .payload = &empty_payload, .unc = 0, .hdr_unc = 0 });
    defer gpa.free(s3);
    const with_empty = try std.mem.concat(gpa, u8, &.{ a, s3, b });
    defer gpa.free(with_empty);
    try expectDecodes("first second", with_empty, .xz, .{});
}

test "xz: a block that holds more than its header says is CorruptData after exactly the declared bytes" {
    const stored = try storedPayload("0123456789abcdefghij");
    defer gpa.free(stored);
    const z = try buildXz(.{ .payload = stored, .unc = 10, .hdr_unc = 10 });
    defer gpa.free(z);
    var in: Reader = .fixed(z);
    var d = try lzma.Decoder.init(gpa, &in, .xz, .{});
    defer d.deinit();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    try testing.expectError(error.CorruptData, readAllChunked(&d, &got, 7));
    try testing.expectEqualStrings("0123456789", got.items);
    // The decoder stays failed, and an empty destination is answered with 0.
    var one: [4]u8 = undefined;
    try testing.expectError(error.CorruptData, d.read(&one));
    try testing.expectError(error.CorruptData, d.read(&one));
    // An empty destination is answered with 0 and does not disturb a decoder.
    const ok = try buildXz(.{ .payload = stored, .unc = 20 });
    defer gpa.free(ok);
    var in2: Reader = .fixed(ok);
    var d2 = try lzma.Decoder.init(gpa, &in2, .xz, .{});
    defer d2.deinit();
    try testing.expectEqual(@as(usize, 0), try d2.read(one[0..0]));
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(gpa);
    try readAllChunked(&d2, &all, 4);
    try testing.expectEqualStrings("0123456789abcdefghij", all.items);
}

const Sink = struct {
    w: Writer,
    list: std.ArrayList(u8) = .empty,

    fn init(buffer: []u8) Sink {
        return .{ .w = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *Sink = @alignCast(@fieldParentPtr("w", w));
        var total: usize = w.end;
        self.list.appendSlice(gpa, w.buffer[0..w.end]) catch return error.WriteFailed;
        for (data[0 .. data.len - 1]) |d| {
            self.list.appendSlice(gpa, d) catch return error.WriteFailed;
            total += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            self.list.appendSlice(gpa, last) catch return error.WriteFailed;
            total += last.len;
        }
        return w.consume(total);
    }
};

test "decompressStream and DecompressReader: flush, the returned length, the error cause, limit nothing, unbuffered writers" {
    const plain = "the quick brown fox jumps over the lazy dog, the quick brown fox";
    const z = try lzma.compress(gpa, plain, .xz, .{});
    defer gpa.free(z);
    var wb: [32]u8 = undefined;
    var sink = Sink.init(&wb);
    defer sink.list.deinit(gpa);
    var in: Reader = .fixed(z);
    const n = try lzma.decompressStream(gpa, &in, &sink.w, .xz, .{});
    try testing.expectEqual(@as(u64, plain.len), n);
    try testing.expectEqualStrings(plain, sink.list.items);
    // The reader: the cause of a failure is kept, and .nothing is answered with 0.
    var bad = try gpa.dupe(u8, z);
    defer gpa.free(bad);
    bad[bad.len - 14] ^= 0xFF; // in the index/check area: some error
    var in2: Reader = .fixed(bad);
    var rb: [16]u8 = undefined;
    var r = try lzma.DecompressReader.init(gpa, &in2, &rb, .xz, .{});
    defer r.deinit();
    var tmp: [128]u8 = undefined;
    try testing.expectError(error.ReadFailed, r.reader.readSliceAll(&tmp));
    try testing.expect(r.err != null);
    // limit .nothing, unbuffered discarding writer, and variable-size reads over a refilled buffer.
    var in3: Reader = .fixed(z);
    var rb3: [16]u8 = undefined;
    var r3 = try lzma.DecompressReader.init(gpa, &in3, &rb3, .xz, .{});
    defer r3.deinit();
    var empty_buf: [0]u8 = undefined;
    var dis: Writer.Discarding = .init(&empty_buf);
    try testing.expectEqual(@as(usize, 0), try r3.reader.stream(&dis.writer, .limited(0)));
    try testing.expectEqual(@as(usize, plain.len), try r3.reader.streamRemaining(&dis.writer));
    var prng: std.Random.DefaultPrng = .init(3);
    var big: [20_000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i *% 31 +% i / 7);
    const zb = try lzma.compress(gpa, &big, .xz, .{});
    defer gpa.free(zb);
    var in4: Reader = .fixed(zb);
    var rb4: [64]u8 = undefined;
    var r4 = try lzma.DecompressReader.init(gpa, &in4, &rb4, .xz, .{});
    defer r4.deinit();
    var off: usize = 0;
    var got: [40]u8 = undefined;
    while (off < big.len) {
        const k = @min(1 + prng.random().uintLessThan(usize, 40), big.len - off);
        try r4.reader.readSliceAll(got[0..k]);
        try testing.expectEqualSlices(u8, big[off..][0..k], got[0..k]);
        off += k;
    }
}
