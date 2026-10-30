// SPDX-License-Identifier: MIT

//! The bzip2 compressor: initial run-length coding, block sort, MTF and
//! zero-run coding, Huffman table selection and the bit writer. Ported from
//! libbzip2 1.0.8 (bzlib.c's block assembly and compress.c; BSD-style
//! licence, see ../NOTICE; altered: translated to Zig, streaming through a
//! `std.Io.Writer`). For the same input, level and work factor the bytes are
//! the ones `BZ2_bzCompress` produces.

const std = @import("std");
const Writer = std.Io.Writer;
const crc = @import("crc.zig");
const huffman = @import("huffman.zig");
const blocksort = @import("blocksort.zig");
const rnums = @import("randtable.zig").rnums;

const n_groups = 6;
const g_size = 50;
const n_iters = 4;
const max_alpha = huffman.max_alpha_size;
const max_selectors = 2 + 900000 / g_size;

pub const Options = struct {
    /// Block size in units of 100 000 bytes, 1..9 (bzip2's `-1`..`-9`).
    level: u4 = 9,
    /// libbzip2's `workFactor` (0 means its default, 30): how much work the
    /// main block sort may spend before the fallback sort takes over.
    work_factor: u8 = 30,
};

pub const WriteError = Writer.Error || std.mem.Allocator.Error || error{
    /// `finish` was already called (or `write` after it).
    AlreadyFinished,
};
pub const Error = WriteError || error{InvalidLevel};

/// The most bytes `compress` can produce for `n` input bytes (libbzip2's
/// documented bound: 1 % plus 600 bytes, rounded up here).
pub fn compressBound(n: usize) usize {
    // Saturating (sweep BZ-3): a bound for a size no slice has must not overflow.
    return n +| n / 100 +| 700;
}

const Coding = struct {
    len: [n_groups][max_alpha]u8,
    code: [n_groups][max_alpha]u32,
    rfreq: [n_groups][max_alpha]u32,
    mtf_freq: [max_alpha]u32,
    selector: [max_selectors]u8,
    selector_mtf: [max_selectors]u8,
    /// Three tables' lengths per symbol packed in a word each (libbzip2's
    /// `len_pack`), for the common six-table, 50-symbol group.
    len_pack: [max_alpha][3]u32,
};

/// The compressor's state. Memory follows the input: the block buffer grows
/// as bytes arrive (at most `4 * (level * 100 000 + 34)` bytes when a block
/// is sorted), the sort's tables are sized to the block, so a small input
/// costs a few kilobytes and a full level-9 block about 7.5 MB.
pub const Encoder = struct {
    gpa: std.mem.Allocator,
    out: *Writer,
    work_factor: u32,
    block_size_100k: u8,
    nblock_max: u32,

    arr1: []u32,
    arr2: []u32,
    ftab: []u32,
    coding: *Coding,

    nblock: u32 = 0,
    block_crc: u32 = crc.init,
    combined_crc: u32 = 0,
    in_use: [256]bool = @splat(false),
    state_in_ch: u32 = 256,
    state_in_len: u32 = 0,
    header_done: bool = false,
    finished: bool = false,
    /// The first error `write`/`finish` returned (sweep REV-bzip2-2): every
    /// later `write`/`finish` returns it again instead of re-entering a
    /// half-written block. Cleared by `reset`.
    failed: ?WriteError = null,
    /// Test hook: write every block in bzip2 0.9.0's randomised form (the
    /// block bytes XORed with the `randtable` mask, the randomised bit set),
    /// which no encoder since 0.9.5 produces but every decoder must read.
    randomise: bool = false,

    bs_buff: u64 = 0,
    bs_live: u6 = 0,
    obuf: [1024]u8 = undefined,
    olen: usize = 0,

    pub fn init(gpa: std.mem.Allocator, out: *Writer, opts: Options) Error!Encoder {
        if (opts.level < 1 or opts.level > 9) return error.InvalidLevel;
        const n: usize = @as(usize, opts.level) * 100_000;
        const coding = try gpa.create(Coding);
        return .{
            .gpa = gpa,
            .out = out,
            .work_factor = if (opts.work_factor == 0) 30 else opts.work_factor,
            .block_size_100k = opts.level,
            .nblock_max = @intCast(n - 19),
            .arr1 = &.{},
            .arr2 = &.{},
            .ftab = &.{},
            .coding = coding,
        };
    }

    pub fn deinit(e: *Encoder) void {
        e.gpa.free(e.arr1);
        e.gpa.free(e.arr2);
        e.gpa.free(e.ftab);
        e.gpa.destroy(e.coding);
        e.* = undefined;
    }

    /// Restart for a new stream on `out`, keeping the allocations.
    pub fn reset(e: *Encoder, out: *Writer) void {
        e.out = out;
        e.nblock = 0;
        e.block_crc = crc.init;
        e.combined_crc = 0;
        e.in_use = @splat(false);
        e.state_in_ch = 256;
        e.state_in_len = 0;
        e.header_done = false;
        e.finished = false;
        e.failed = null;
        e.bs_buff = 0;
        e.bs_live = 0;
        e.olen = 0;
    }

    inline fn blockBytes(e: *Encoder) []u8 {
        return std.mem.sliceAsBytes(e.arr2);
    }

    // ── input side (bzlib.c) ────────────────────────────────────────────

    /// `arr2` (the block's bytes, then the sort's scratch) holds at least
    /// `u32s` words.
    fn ensureArr2(e: *Encoder, u32s: usize) std.mem.Allocator.Error!void {
        if (e.arr2.len >= u32s) return;
        const cap: usize = @as(usize, e.block_size_100k) * 100_000 + blocksort.n_overshoot;
        const want = @min(cap, @max(u32s, e.arr2.len * 2, 4096));
        e.arr2 = try e.gpa.realloc(e.arr2, want);
    }

    fn addPairToBlock(e: *Encoder) std.mem.Allocator.Error!void {
        const ch: u8 = @intCast(e.state_in_ch);
        const len = e.state_in_len;
        try e.ensureArr2((e.nblock + 5) / 4 + 1);
        e.block_crc = crc.updateRun(e.block_crc, ch, len);
        e.in_use[ch] = true;
        const block = e.blockBytes();
        var nb = e.nblock;
        if (len < 4) {
            @memset(block[nb..][0..len], ch);
            nb += len;
        } else {
            e.in_use[len - 4] = true;
            @memset(block[nb..][0..4], ch);
            block[nb + 4] = @intCast(len - 4);
            nb += 5;
        }
        e.nblock = nb;
    }

    /// Feed `data` to the compressor; whole blocks go out as they fill.
    pub fn write(e: *Encoder, data: []const u8) WriteError!void {
        if (e.failed) |f| return f;
        if (e.finished) return error.AlreadyFinished;
        e.writeInner(data) catch |err| {
            e.failed = err;
            return err;
        };
    }

    fn writeInner(e: *Encoder, data: []const u8) WriteError!void {
        var i: usize = 0;
        while (i < data.len) {
            if (e.nblock >= e.nblock_max) {
                try e.compressBlock(false);
                e.prepareNewBlock();
                continue;
            }
            // Fast stretch: bytes that extend the pending run are counted
            // without touching the block.
            const c: u32 = data[i];
            if (c == e.state_in_ch and e.state_in_len < 255) {
                e.state_in_len += 1;
            } else {
                if (e.state_in_ch < 256) try e.addPairToBlock();
                e.state_in_ch = c;
                e.state_in_len = 1;
            }
            i += 1;
        }
    }

    fn prepareNewBlock(e: *Encoder) void {
        e.nblock = 0;
        e.block_crc = crc.init;
        e.in_use = @splat(false);
    }

    /// Ends the stream: the pending run, the last block and the trailer.
    /// `out` is not flushed.
    pub fn finish(e: *Encoder) WriteError!void {
        if (e.failed) |f| return f;
        // Single-shot: a second call would write a second trailer (the
        // assert this was is a no-op in ReleaseFast).
        if (e.finished) return error.AlreadyFinished;
        e.finishInner() catch |err| {
            e.failed = err;
            return err;
        };
    }

    fn finishInner(e: *Encoder) WriteError!void {
        // libbzip2 closes a block that filled up as the last byte of a
        // `BZ_RUN` call went in before `BZ_FINISH` flushes the pending run,
        // which then lands in a block of its own.
        if (e.nblock >= e.nblock_max) {
            try e.compressBlock(false);
            e.prepareNewBlock();
        }
        if (e.state_in_ch < 256) try e.addPairToBlock();
        e.state_in_ch = 256;
        e.state_in_len = 0;
        try e.compressBlock(true);
        e.finished = true;
        try e.flushObuf();
    }

    // ── bit writer ──────────────────────────────────────────────────────

    inline fn bsW(e: *Encoder, n: u6, v: u32) Writer.Error!void {
        e.bs_buff = (e.bs_buff << n) | v;
        e.bs_live += n;
        if (e.bs_live >= 32) {
            e.bs_live -= 32;
            if (e.olen + 4 > e.obuf.len) try e.flushObuf();
            std.mem.writeInt(u32, e.obuf[e.olen..][0..4], @truncate(e.bs_buff >> e.bs_live), .big);
            e.olen += 4;
        }
    }

    fn flushObuf(e: *Encoder) Writer.Error!void {
        try e.out.writeAll(e.obuf[0..e.olen]);
        e.olen = 0;
    }

    /// Pads to a byte and writes out what is left.
    fn bsFinish(e: *Encoder) Writer.Error!void {
        while (e.bs_live > 0) {
            const take: u6 = @min(e.bs_live, 8);
            if (e.olen == e.obuf.len) try e.flushObuf();
            // The next byte: the top `take` bits of what is pending, zero padded.
            const bitsv: u64 = (e.bs_buff >> (e.bs_live - take)) & ((@as(u64, 1) << take) - 1);
            e.obuf[e.olen] = @intCast(bitsv << (8 - take));
            e.olen += 1;
            e.bs_live -= take;
        }
    }

    // ── compress.c ──────────────────────────────────────────────────────

    fn compressBlock(e: *Encoder, is_last: bool) WriteError!void {
        var orig_ptr: u32 = 0;
        var blk_crc: u32 = 0;
        if (e.nblock > 0) {
            if (e.randomise) e.randomiseBlock();
            blk_crc = crc.finalize(e.block_crc);
            e.combined_crc = crc.combine(e.combined_crc, blk_crc);
            try e.prepareSort();
            orig_ptr = blocksort.blockSort(e.arr1, e.arr2, e.ftab, e.nblock, e.work_factor);
        }

        if (!e.header_done) {
            e.header_done = true;
            try e.bsW(8, 'B');
            try e.bsW(8, 'Z');
            try e.bsW(8, 'h');
            try e.bsW(8, '0' + e.block_size_100k);
        }

        if (e.nblock > 0) {
            try e.bsW(24, 0x314159);
            try e.bsW(24, 0x265359);
            try e.bsW(16, blk_crc >> 16);
            try e.bsW(16, blk_crc & 0xffff);
            try e.bsW(1, @intFromBool(e.randomise));
            try e.bsW(24, orig_ptr);
            const n_mtf = e.generateMtfValues();
            try e.sendMtfValues(n_mtf);
        }

        if (is_last) {
            try e.bsW(24, 0x177245);
            try e.bsW(24, 0x385090);
            try e.bsW(16, e.combined_crc >> 16);
            try e.bsW(16, e.combined_crc & 0xffff);
            try e.bsFinish();
        }
    }

    /// The sort's arrays, sized to this block.
    fn prepareSort(e: *Encoder) std.mem.Allocator.Error!void {
        const nb: usize = e.nblock;
        try e.ensureArr2(nb + blocksort.n_overshoot);
        if (e.arr1.len < nb) {
            e.gpa.free(e.arr1);
            e.arr1 = &.{};
            e.arr1 = try e.gpa.alloc(u32, nb);
        }
        const ftab_len: usize = if (nb >= 10_000) 65537 else (nb + 64) / 32 + 4;
        if (e.ftab.len < ftab_len) {
            e.gpa.free(e.ftab);
            e.ftab = &.{};
            e.ftab = try e.gpa.alloc(u32, ftab_len);
        }
    }

    fn randomiseBlock(e: *Encoder) void {
        const block = e.blockBytes()[0..e.nblock];
        var to_go: u32 = 0;
        var pos: usize = 0;
        e.in_use = @splat(false);
        for (block) |*b| {
            if (to_go == 0) {
                to_go = rnums[pos];
                pos = (pos + 1) % 512;
            }
            to_go -= 1;
            if (to_go == 1) b.* ^= 1;
            e.in_use[b.*] = true;
        }
    }

    fn mtfv(e: *Encoder) []u16 {
        return @ptrCast(e.arr1);
    }

    fn generateMtfValues(e: *Encoder) u32 {
        const ptr = e.arr1;
        const block = e.blockBytes();
        const mv = e.mtfv();
        const freq = &e.coding.mtf_freq;
        const nblock = e.nblock;

        var unseq_to_seq: [256]u8 = undefined;
        var n_in_use: u32 = 0;
        for (0..256) |i| if (e.in_use[i]) {
            unseq_to_seq[i] = @intCast(n_in_use);
            n_in_use += 1;
        };
        const eob: u32 = n_in_use + 1;
        @memset(freq[0 .. eob + 1], 0);

        var yy: [256]u8 = undefined;
        for (0..n_in_use) |i| yy[i] = @intCast(i);

        var wr: usize = 0;
        var z_pend: u32 = 0;
        for (0..nblock) |i| {
            var j: i64 = @as(i64, ptr[i]) - 1;
            if (j < 0) j += nblock;
            const ll_i = unseq_to_seq[block[@intCast(j)]];

            if (yy[0] == ll_i) {
                z_pend += 1;
            } else {
                if (z_pend > 0) {
                    wr = emitRun(mv, freq, wr, z_pend);
                    z_pend = 0;
                }
                var rtmp = yy[1];
                yy[1] = yy[0];
                var k: usize = 1;
                while (ll_i != rtmp) {
                    k += 1;
                    const rtmp2 = rtmp;
                    rtmp = yy[k];
                    yy[k] = rtmp2;
                }
                yy[0] = rtmp;
                mv[wr] = @intCast(k + 1);
                wr += 1;
                freq[k + 1] += 1;
            }
        }
        if (z_pend > 0) wr = emitRun(mv, freq, wr, z_pend);

        mv[wr] = @intCast(eob);
        wr += 1;
        freq[eob] += 1;
        return @intCast(wr);
    }

    /// Bijective base-2 run-length code (RUNA/RUNB) of `z_pend` zeros.
    fn emitRun(mv: []u16, freq: *[max_alpha]u32, wr_in: usize, z_pend_in: u32) usize {
        var wr = wr_in;
        var z = z_pend_in - 1;
        while (true) {
            if (z & 1 != 0) {
                mv[wr] = 1;
                freq[1] += 1;
            } else {
                mv[wr] = 0;
                freq[0] += 1;
            }
            wr += 1;
            if (z < 2) break;
            z = (z - 2) / 2;
        }
        return wr;
    }

    fn sendMtfValues(e: *Encoder, n_mtf: u32) Writer.Error!void {
        const c = e.coding;
        const mv = e.mtfv()[0..n_mtf];
        var n_in_use: u32 = 0;
        for (e.in_use) |u| n_in_use += @intFromBool(u);
        const alpha_size: usize = n_in_use + 2;

        for (0..n_groups) |t| @memset(c.len[t][0..alpha_size], 15);

        const ng: usize = if (n_mtf < 200) 2 else if (n_mtf < 600) 3 else if (n_mtf < 1200) 4 else if (n_mtf < 2400) 5 else 6;

        {
            var n_part: usize = ng;
            var rem_f: i64 = n_mtf;
            var gs: i64 = 0;
            while (n_part > 0) {
                const t_freq = @divTrunc(rem_f, @as(i64, @intCast(n_part)));
                var ge = gs - 1;
                var a_freq: i64 = 0;
                while (a_freq < t_freq and ge < @as(i64, @intCast(alpha_size)) - 1) {
                    ge += 1;
                    a_freq += c.mtf_freq[@intCast(ge)];
                }
                if (ge > gs and n_part != ng and n_part != 1 and ((ng - n_part) % 2 == 1)) {
                    a_freq -= c.mtf_freq[@intCast(ge)];
                    ge -= 1;
                }
                for (0..alpha_size) |v| {
                    const vi: i64 = @intCast(v);
                    c.len[n_part - 1][v] = if (vi >= gs and vi <= ge) 0 else 15;
                }
                n_part -= 1;
                gs = ge + 1;
                rem_f -= a_freq;
            }
        }

        var n_selectors: usize = 0;
        for (0..n_iters) |_| {
            for (0..ng) |t| @memset(c.rfreq[t][0..alpha_size], 0);

            if (ng == 6) for (0..alpha_size) |v| {
                c.len_pack[v][0] = (@as(u32, c.len[1][v]) << 16) | c.len[0][v];
                c.len_pack[v][1] = (@as(u32, c.len[3][v]) << 16) | c.len[2][v];
                c.len_pack[v][2] = (@as(u32, c.len[5][v]) << 16) | c.len[4][v];
            };

            n_selectors = 0;
            var gs: usize = 0;
            while (gs < n_mtf) {
                const ge = @min(gs + g_size, n_mtf);
                var cost: [n_groups]u16 = @splat(0);
                if (ng == 6 and ge - gs == g_size) {
                    var c01: u32 = 0;
                    var c23: u32 = 0;
                    var c45: u32 = 0;
                    for (mv[gs..ge]) |icv| {
                        const lp = &c.len_pack[icv];
                        c01 += lp[0];
                        c23 += lp[1];
                        c45 += lp[2];
                    }
                    cost = .{ @truncate(c01), @intCast(c01 >> 16), @truncate(c23), @intCast(c23 >> 16), @truncate(c45), @intCast(c45 >> 16) };
                } else {
                    for (mv[gs..ge]) |icv| {
                        for (0..ng) |t| cost[t] += c.len[t][icv];
                    }
                }
                var bc: u32 = 999999999;
                var bt: usize = 0;
                for (0..ng) |t| if (cost[t] < bc) {
                    bc = cost[t];
                    bt = t;
                };
                c.selector[n_selectors] = @intCast(bt);
                n_selectors += 1;
                const rf = &c.rfreq[bt];
                for (mv[gs..ge]) |icv| rf[icv] += 1;
                gs = ge;
            }

            for (0..ng) |t| huffman.makeCodeLengths(&c.len[t], &c.rfreq[t], alpha_size, huffman.encode_max_len);
        }

        // Selectors, MTF-coded.
        {
            var pos: [n_groups]u8 = undefined;
            for (0..ng) |i| pos[i] = @intCast(i);
            for (0..n_selectors) |i| {
                const ll_i = c.selector[i];
                var j: usize = 0;
                var tmp = pos[0];
                while (ll_i != tmp) {
                    j += 1;
                    const tmp2 = tmp;
                    tmp = pos[j];
                    pos[j] = tmp2;
                }
                pos[0] = tmp;
                c.selector_mtf[i] = @intCast(j);
            }
        }

        for (0..ng) |t| {
            var min_len: u32 = 32;
            var max_len: u32 = 0;
            for (c.len[t][0..alpha_size]) |l| {
                if (l > max_len) max_len = l;
                if (l < min_len) min_len = l;
            }
            huffman.assignCodes(&c.code[t], &c.len[t], min_len, max_len, alpha_size);
        }

        // The symbol map.
        {
            var in16: [16]bool = @splat(false);
            for (0..16) |i| for (0..16) |j| if (e.in_use[i * 16 + j]) {
                in16[i] = true;
            };
            for (0..16) |i| try e.bsW(1, @intFromBool(in16[i]));
            for (0..16) |i| if (in16[i]) {
                for (0..16) |j| try e.bsW(1, @intFromBool(e.in_use[i * 16 + j]));
            };
        }

        try e.bsW(3, @intCast(ng));
        try e.bsW(15, @intCast(n_selectors));
        for (0..n_selectors) |i| {
            for (0..c.selector_mtf[i]) |_| try e.bsW(1, 1);
            try e.bsW(1, 0);
        }

        for (0..ng) |t| {
            var curr: u32 = c.len[t][0];
            try e.bsW(5, curr);
            for (0..alpha_size) |i| {
                while (curr < c.len[t][i]) {
                    try e.bsW(2, 2);
                    curr += 1;
                }
                while (curr > c.len[t][i]) {
                    try e.bsW(2, 3);
                    curr -= 1;
                }
                try e.bsW(1, 0);
            }
        }

        var sel_ctr: usize = 0;
        var gs: usize = 0;
        while (gs < n_mtf) {
            const ge = @min(gs + g_size, n_mtf);
            const sel = c.selector[sel_ctr];
            const lens = &c.len[sel];
            const codes = &c.code[sel];
            for (mv[gs..ge]) |sym| try e.bsW(@intCast(lens[sym]), codes[sym]);
            gs = ge;
            sel_ctr += 1;
        }
    }
};

/// Compress `input` into a complete .bz2 stream. Caller owns the result.
pub fn compress(gpa: std.mem.Allocator, input: []const u8, opts: Options) Error![]u8 {
    var out: Writer.Allocating = try .initCapacity(gpa, @min(compressBound(input.len), 1 << 20));
    errdefer out.deinit();
    var enc = try Encoder.init(gpa, &out.writer, opts);
    defer enc.deinit();
    try enc.write(input);
    try enc.finish();
    return out.toOwnedSlice();
}

/// `compress` into the caller's buffer; `error.OutputTooLarge` when it does
/// not fit (`compressBound(input.len)` bytes always do). Returns the length.
pub fn compressInto(gpa: std.mem.Allocator, dest: []u8, input: []const u8, opts: Options) (Error || error{OutputTooLarge})!usize {
    var w: Writer = .fixed(dest);
    var enc = try Encoder.init(gpa, &w, opts);
    defer enc.deinit();
    enc.write(input) catch |e| return if (e == error.WriteFailed) error.OutputTooLarge else e;
    enc.finish() catch |e| return if (e == error.WriteFailed) error.OutputTooLarge else e;
    return w.end;
}

/// A `std.Io.Writer` that compresses what is written to it into one .bz2
/// stream on `output`. Call `finish` to end the stream (it does not flush
/// `output`); there is no sync-flush: bytes reach `output` as blocks fill.
pub const StreamWriter = struct {
    /// The interface. Its buffer is the one passed to `init`.
    writer: Writer,
    enc: Encoder,
    /// Why the last `error.WriteFailed` came from here rather than from the
    /// output. Null when the output failed.
    err: ?std.mem.Allocator.Error = null,

    const vtable: Writer.VTable = .{ .drain = drain };

    /// `buffer` may be empty. `gpa` holds the compressor's tables.
    pub fn init(gpa: std.mem.Allocator, output: *Writer, buffer: []u8, opts: Options) Error!StreamWriter {
        return .{
            .writer = .{ .buffer = buffer, .vtable = &vtable },
            .enc = try .init(gpa, output, opts),
        };
    }

    pub fn deinit(sw: *StreamWriter) void {
        sw.enc.deinit();
        sw.* = undefined;
    }

    /// The buffered bytes, the last block and the trailer; then the writer
    /// accepts nothing more. Idempotent: a call after a successful `finish`
    /// does nothing (sweep REV-bzip2-1); after a failure it returns
    /// `error.WriteFailed` again.
    pub fn finish(sw: *StreamWriter) Writer.Error!void {
        if (sw.enc.finished and sw.enc.failed == null) return;
        const w = &sw.writer;
        try sw.feed(w.buffer[0..w.end]);
        w.end = 0;
        sw.enc.finish() catch |e| return sw.fail(e);
        w.* = .failing;
    }

    fn fail(sw: *StreamWriter, e: WriteError) Writer.Error {
        // Only an allocation failure is recorded in `err`; anything else
        // (WriteFailed, AlreadyFinished) must not be cast into its type.
        if (e == error.OutOfMemory) sw.err = error.OutOfMemory;
        return error.WriteFailed;
    }

    fn feed(sw: *StreamWriter, bytes: []const u8) Writer.Error!void {
        sw.enc.write(bytes) catch |e| return sw.fail(e);
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const sw: *StreamWriter = @alignCast(@fieldParentPtr("writer", w));
        try sw.feed(w.buffer[0..w.end]);
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try sw.feed(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try sw.feed(last);
        return n + last.len * splat;
    }
};
