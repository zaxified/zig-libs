// SPDX-License-Identifier: MIT

//! The bzip2 decompressor: concatenated .bz2 streams, block and stream CRCs
//! checked, randomised blocks of bzip2 0.9.0 handled, memory bounded by one
//! block (4 bytes per block symbol, at most 3.6 MB for -9, grown as the
//! block decodes, plus ~25 KB of tables). The format checks follow libbzip2 1.0.8's decompress.c (BSD-style
//! licence, see ../NOTICE; altered: rewritten in Zig around a pull
//! `std.Io.Reader`, the Huffman decode done on a 20-bit window instead of bit
//! by bit). Malformed input returns a typed error and never panics.

const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const crc = @import("crc.zig");
const huffman = @import("huffman.zig");
const rnums = @import("randtable.zig").rnums;

const n_groups = 6;
const g_size = 50;
const max_alpha = huffman.max_alpha_size;
const max_selectors = 2 + 900000 / g_size;

pub const Error = error{
    /// Not a "BZh1".."BZh9" header.
    BadMagic,
    /// The 48-bit block header is neither a block nor the stream trailer.
    BadBlockHeader,
    /// The stream trailer's magic is wrong.
    BadTrailer,
    /// The block's origin pointer is outside the block.
    BadOrigPtr,
    /// A block that uses no byte value at all.
    BadSymbolMap,
    /// Coding tables or selectors that cannot be (group count, selector
    /// count, selector value, code length outside 1..20).
    BadTables,
    /// A Huffman code that no symbol has.
    BadCode,
    /// More symbols than the stream's block size holds.
    BlockOverflow,
    /// A run-length symbol sequence that decodes to an absurd length.
    BadRun,
    /// The block's run-length data is inconsistent.
    BadBlockData,
    BlockCrcMismatch,
    StreamCrcMismatch,
    /// The input ended inside a stream.
    TruncatedInput,
    /// `Options.max_output` would be exceeded.
    OutputTooLarge,
    /// Bytes after the last stream that do not start another stream
    /// (`Options.ignore_trailing_garbage` turns this off).
    TrailingData,
    OutOfMemory,
    ReadFailed,
};

pub const Options = struct {
    /// Decompression-bomb cap: at most this many output bytes in total;
    /// more is `error.OutputTooLarge`. Memory is bounded by the block size
    /// regardless; this bounds the output.
    max_output: ?u64 = null,
    /// Read every stream until the input ends (bzip2, Python's `BZ2File` and
    /// libzip do). False stops after the first stream.
    multi_stream: bool = true,
    /// After a complete stream, bytes that do not start another one end the
    /// output quietly (bzip2 prints a warning and exits 0; Python ignores
    /// them) instead of `error.TrailingData`.
    ignore_trailing_garbage: bool = false,
};

const Work = struct {
    tables: [n_groups]huffman.DecodeTable,
    selector: [max_selectors]u8,
    selector_mtf: [max_selectors]u8,
    len: [n_groups][max_alpha]u8,
    seq_to_unseq: [256]u8,
    cftab: [257]u32,
};

const Phase = enum { stream_header, block_header, block_output, done };

/// The decoder core, pulling bytes from `in`.
pub const Decoder = struct {
    gpa: std.mem.Allocator,
    in: *Reader,
    opts: Options,
    work: *Work,
    tt: []u32 = &.{},

    acc: u64 = 0,
    nbits: u8 = 0,
    /// Fake zero bits at the low end of `acc`, appended once `in` ran dry;
    /// consuming one is `error.TruncatedInput`.
    pad: u8 = 0,

    phase: Phase = .stream_header,
    streams: u32 = 0,
    block_size_100k: u32 = 0,
    nblock: u32 = 0,
    randomised: bool = false,
    stored_block_crc: u32 = 0,
    combined_crc: u32 = 0,
    stored_combined: u32 = 0,
    // unRLE state
    block_crc: u32 = crc.init,
    tpos: u32 = 0,
    used: u32 = 0,
    k0: u8 = 0,
    out_ch: u8 = 0,
    out_len: u32 = 0,
    rand_to_go: u32 = 0,
    rand_pos: u32 = 0,
    total_out: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, in: *Reader, opts: Options) error{OutOfMemory}!Decoder {
        return .{ .gpa = gpa, .in = in, .opts = opts, .work = try gpa.create(Work) };
    }

    pub fn deinit(d: *Decoder) void {
        d.gpa.free(d.tt);
        d.gpa.destroy(d.work);
        d.* = undefined;
    }

    // ── bit input ───────────────────────────────────────────────────────

    fn refill(d: *Decoder) error{ReadFailed}!void {
        while (d.nbits <= 56) {
            var buf = d.in.buffered();
            if (buf.len == 0) {
                d.in.fill(1) catch |e| switch (e) {
                    error.ReadFailed => return error.ReadFailed,
                    error.EndOfStream => {
                        while (d.nbits <= 56) {
                            d.acc <<= 8;
                            d.nbits += 8;
                            d.pad += 8;
                        }
                        return;
                    },
                };
                buf = d.in.buffered();
            }
            const room: usize = (64 - @as(usize, d.nbits)) >> 3;
            const k = @min(room, buf.len);
            if (buf.len >= 8 and room == 8) {
                d.acc = std.mem.readInt(u64, buf[0..8], .big);
            } else if (buf.len >= 8) {
                const x = std.mem.readInt(u64, buf[0..8], .big);
                const sh: u6 = @intCast(8 * k);
                d.acc = (d.acc << sh) | (x >> @intCast(64 - 8 * k));
            } else {
                for (buf[0..k]) |b| d.acc = (d.acc << 8) | b;
            }
            d.nbits += @intCast(8 * k);
            d.in.toss(k);
        }
    }

    inline fn need(d: *Decoder) error{ReadFailed}!void {
        if (d.nbits < 32) try d.refill();
    }

    inline fn peek(d: *const Decoder, n: u6) u32 {
        return @truncate((d.acc >> @intCast(d.nbits - n)) & ((@as(u64, 1) << n) - 1));
    }

    inline fn consume(d: *Decoder, n: u8) error{TruncatedInput}!void {
        d.nbits -= n;
        if (d.nbits < d.pad) return error.TruncatedInput;
    }

    /// `n` <= 24 bits.
    fn bits(d: *Decoder, n: u6) (error{ ReadFailed, TruncatedInput })!u32 {
        try d.need();
        const v = d.peek(n);
        try d.consume(n);
        return v;
    }

    inline fn bit(d: *Decoder) (error{ ReadFailed, TruncatedInput })!u32 {
        return d.bits(1);
    }

    // ── structure ───────────────────────────────────────────────────────

    fn realBitsLeft(d: *const Decoder) u32 {
        return d.nbits - d.pad;
    }

    /// Reads "BZh" + level. `null` at a clean end of input (after a stream).
    fn streamHeader(d: *Decoder) Error!bool {
        // Byte-align after the previous stream's trailer.
        d.nbits -= d.nbits % 8;
        try d.need();
        if (d.streams > 0 and d.realBitsLeft() == 0) return false;
        const b = try d.bits(8);
        const z = try d.bits(8);
        const h = try d.bits(8);
        const l = try d.bits(8);
        if (b != 'B' or z != 'Z' or h != 'h' or l < '1' or l > '9') return error.BadMagic;
        d.block_size_100k = l - '0';
        d.combined_crc = 0;
        d.streams += 1;
        return true;
    }

    /// Reads the next block header and decodes the block into `tt`, or
    /// reads the stream trailer. Returns true when a block is ready.
    fn blockHeader(d: *Decoder) Error!bool {
        const b0 = try d.bits(8);
        if (b0 == 0x17) {
            const t = [_]u32{ 0x72, 0x45, 0x38, 0x50, 0x90 };
            for (t) |want| if (try d.bits(8) != want) return error.BadTrailer;
            var s: u32 = 0;
            for (0..4) |_| s = (s << 8) | try d.bits(8);
            if (s != d.combined_crc) return error.StreamCrcMismatch;
            return false;
        }
        if (b0 != 0x31) return error.BadBlockHeader;
        for ([_]u32{ 0x41, 0x59, 0x26, 0x53, 0x59 }) |want| if (try d.bits(8) != want) return error.BadBlockHeader;
        var s: u32 = 0;
        for (0..4) |_| s = (s << 8) | try d.bits(8);
        d.stored_block_crc = s;
        d.randomised = (try d.bit()) == 1;
        var orig: u32 = 0;
        for (0..3) |_| orig = (orig << 8) | try d.bits(8);
        if (orig > 10 + 100_000 * d.block_size_100k) return error.BadOrigPtr;

        try d.decodeBlock(orig);
        return true;
    }

    /// `tt` holds at least `at_least` entries (at most `max`): it grows with the
    /// block, so a small stream costs kilobytes, not the block size.
    fn growTt(d: *Decoder, at_least: usize, max: usize) error{OutOfMemory}![]u32 {
        const want = @min(max, @max(at_least, d.tt.len * 2, 16 * 1024));
        d.tt = try d.gpa.realloc(d.tt, want);
        return d.tt;
    }

    fn decodeBlock(d: *Decoder, orig_ptr: u32) Error!void {
        const w = d.work;

        // Symbol map.
        var in16: u32 = 0;
        for (0..16) |_| in16 = (in16 << 1) | try d.bit();
        var n_in_use: u32 = 0;
        for (0..16) |i| {
            if ((in16 >> @intCast(15 - i)) & 1 == 0) continue;
            const m = try d.bits(16);
            for (0..16) |j| {
                if ((m >> @intCast(15 - j)) & 1 != 0) {
                    w.seq_to_unseq[n_in_use] = @intCast(i * 16 + j);
                    n_in_use += 1;
                }
            }
        }
        if (n_in_use == 0) return error.BadSymbolMap;
        @memset(w.seq_to_unseq[n_in_use..], 0);
        const alpha_size: usize = n_in_use + 2;

        // Selectors.
        const ng = try d.bits(3);
        if (ng < 2 or ng > n_groups) return error.BadTables;
        var n_sel: u32 = try d.bits(15);
        if (n_sel < 1) return error.BadTables;
        for (0..n_sel) |i| {
            var j: u8 = 0;
            while (true) {
                if ((try d.bit()) == 0) break;
                j += 1;
                if (j >= ng) return error.BadTables;
            }
            if (i < max_selectors) w.selector_mtf[i] = j;
        }
        if (n_sel > max_selectors) n_sel = max_selectors;
        {
            var pos: [n_groups]u8 = undefined;
            for (0..ng) |v| pos[v] = @intCast(v);
            for (0..n_sel) |i| {
                var v = w.selector_mtf[i];
                const tmp = pos[v];
                while (v > 0) : (v -= 1) pos[v] = pos[v - 1];
                pos[0] = tmp;
                w.selector[i] = tmp;
            }
        }

        // Coding tables.
        for (0..ng) |t| {
            var curr: i32 = @intCast(try d.bits(5));
            for (0..alpha_size) |i| {
                while (true) {
                    if (curr < 1 or curr > huffman.decode_max_len) return error.BadTables;
                    if ((try d.bit()) == 0) break;
                    if ((try d.bit()) == 0) curr += 1 else curr -= 1;
                }
                w.len[t][i] = @intCast(curr);
            }
            w.tables[t].init(&w.len[t], alpha_size);
        }

        // The MTF values.
        const eob: u32 = @intCast(n_in_use + 1);
        const nblock_max = 100_000 * d.block_size_100k;
        var tt = d.tt;
        var unzftab: [256]u32 = @splat(0);
        var mtf: [256]u8 = undefined;
        for (&mtf, 0..) |*m, i| m.* = @intCast(i);

        var nblock: u32 = 0;
        var group_no: u32 = 0;
        var group_pos: u32 = 0;
        var tbl: *const huffman.DecodeTable = &w.tables[0];
        var first = true;

        // `nextSym` is spelled out in a loop: refill when under 32 bits, a
        // 20-bit window, then the canonical-code walk.
        var sym: u32 = 0;
        var have_sym = false;
        while (true) {
            if (!have_sym) {
                if (group_pos == 0) {
                    if (first) {
                        first = false;
                    } else group_no += 1;
                    if (group_no >= n_sel) return error.BadTables;
                    group_pos = g_size;
                    tbl = &w.tables[w.selector[group_no]];
                }
                group_pos -= 1;
                try d.need();
                const win: u32 = @truncate((d.acc >> @intCast(d.nbits - 20)) & 0xf_ffff);
                var zn: u32 = tbl.min_len;
                var zvec: i32 = @intCast(win >> @intCast(20 - zn));
                while (true) {
                    if (zn > huffman.decode_max_len) return error.BadCode;
                    if (zvec <= tbl.limit[zn]) break;
                    zn += 1;
                    if (zn > huffman.decode_max_len) return error.BadCode;
                    zvec = @intCast(win >> @intCast(20 - zn));
                }
                const idx = zvec - tbl.base[zn];
                if (idx < 0 or idx >= max_alpha) return error.BadCode;
                try d.consume(@intCast(zn));
                sym = tbl.perm[@intCast(idx)];
            }
            have_sym = false;

            if (sym == eob) break;

            if (sym <= 1) {
                var es: u32 = 0;
                var n: u32 = 1;
                while (true) {
                    if (n >= 2 * 1024 * 1024) return error.BadRun;
                    es += (sym + 1) * n;
                    n *= 2;
                    // next symbol
                    if (group_pos == 0) {
                        group_no += 1;
                        if (group_no >= n_sel) return error.BadTables;
                        group_pos = g_size;
                        tbl = &w.tables[w.selector[group_no]];
                    }
                    group_pos -= 1;
                    try d.need();
                    const win: u32 = @truncate((d.acc >> @intCast(d.nbits - 20)) & 0xf_ffff);
                    var zn: u32 = tbl.min_len;
                    var zvec: i32 = @intCast(win >> @intCast(20 - zn));
                    while (true) {
                        if (zn > huffman.decode_max_len) return error.BadCode;
                        if (zvec <= tbl.limit[zn]) break;
                        zn += 1;
                        if (zn > huffman.decode_max_len) return error.BadCode;
                        zvec = @intCast(win >> @intCast(20 - zn));
                    }
                    const idx = zvec - tbl.base[zn];
                    if (idx < 0 or idx >= max_alpha) return error.BadCode;
                    try d.consume(@intCast(zn));
                    sym = tbl.perm[@intCast(idx)];
                    if (sym > 1) break;
                }
                have_sym = true;
                const uc = w.seq_to_unseq[mtf[0]];
                unzftab[uc] += es;
                if (es > nblock_max - nblock) return error.BlockOverflow;
                if (nblock + es > tt.len) tt = try d.growTt(nblock + es, nblock_max);
                @memset(tt[nblock..][0..es], uc);
                nblock += es;
                continue;
            }

            if (nblock >= nblock_max) return error.BlockOverflow;
            if (nblock >= tt.len) tt = try d.growTt(nblock + 1, nblock_max);
            const nn = sym - 1;
            const v = mtf[nn];
            std.mem.copyBackwards(u8, mtf[1 .. nn + 1], mtf[0..nn]);
            mtf[0] = v;
            const uc = w.seq_to_unseq[v];
            unzftab[uc] += 1;
            tt[nblock] = uc;
            nblock += 1;
        }

        if (orig_ptr >= nblock) return error.BadOrigPtr;

        // T^-1.
        w.cftab[0] = 0;
        for (1..257) |i| w.cftab[i] = unzftab[i - 1];
        for (1..257) |i| w.cftab[i] += w.cftab[i - 1];
        for (0..nblock) |i| {
            const uc: u8 = @truncate(tt[i]);
            tt[w.cftab[uc]] |= @as(u32, @intCast(i)) << 8;
            w.cftab[uc] += 1;
        }

        d.nblock = nblock;
        d.block_crc = crc.init;
        d.out_len = 0;
        d.out_ch = 0;
        d.rand_to_go = 0;
        d.rand_pos = 0;
        d.tpos = tt[orig_ptr] >> 8;
        d.used = 0;
        d.k0 = if (d.randomised) d.fetch(true) else d.fetch(false);
        d.used = 1;
    }

    inline fn fetch(d: *Decoder, comptime randomised: bool) u8 {
        d.tpos = d.tt[d.tpos];
        var ch: u8 = @truncate(d.tpos);
        d.tpos >>= 8;
        if (randomised) {
            if (d.rand_to_go == 0) {
                d.rand_to_go = rnums[d.rand_pos];
                d.rand_pos += 1;
                if (d.rand_pos == 512) d.rand_pos = 0;
            }
            d.rand_to_go -= 1;
            if (d.rand_to_go == 1) ch ^= 1;
        }
        return ch;
    }

    /// Undo the initial run-length coding of the current block into `dest`.
    /// Returns 0 when the block is used up.
    fn unRle(d: *Decoder, dest: []u8) Error!usize {
        return switch (d.randomised) {
            inline else => |r| d.unRleImpl(dest, r),
        };
    }

    fn unRleImpl(d: *Decoder, dest: []u8, comptime randomised: bool) Error!usize {
        const end = d.nblock + 1;
        var n: usize = 0;
        var used = d.used;
        var k0 = d.k0;
        var out_ch = d.out_ch;
        var out_len = d.out_len;
        defer {
            d.used = used;
            d.k0 = k0;
            d.out_ch = out_ch;
            d.out_len = out_len;
        }
        while (true) {
            if (out_len > 0) {
                const k = @min(out_len, dest.len - n);
                @memset(dest[n..][0..k], out_ch);
                n += k;
                out_len -= @intCast(k);
                if (out_len > 0) break;
            }
            if (n == dest.len) break;
            if (used > end) return error.BadBlockData;
            if (used == end) break;
            out_ch = k0;
            out_len = 1;
            var k1 = d.fetch(randomised);
            used += 1;
            if (used == end) continue;
            if (k1 != k0) {
                k0 = k1;
                continue;
            }
            out_len = 2;
            k1 = d.fetch(randomised);
            used += 1;
            if (used == end) continue;
            if (k1 != k0) {
                k0 = k1;
                continue;
            }
            out_len = 3;
            k1 = d.fetch(randomised);
            used += 1;
            if (used == end) continue;
            if (k1 != k0) {
                k0 = k1;
                continue;
            }
            k1 = d.fetch(randomised);
            used += 1;
            out_len = @as(u32, k1) + 4;
            k0 = d.fetch(randomised);
            used += 1;
        }
        d.block_crc = crc.update(d.block_crc, dest[0..n]);
        return n;
    }

    /// Decompressed bytes into `dest`; 0 means the end of the last stream.
    pub fn read(d: *Decoder, dest: []u8) Error!usize {
        std.debug.assert(dest.len > 0);
        while (true) switch (d.phase) {
            .done => return 0,
            .stream_header => {
                if (d.streams > 0 and !d.opts.multi_stream) {
                    d.phase = .done;
                    continue;
                }
                const had_stream = d.streams > 0;
                // A second stream that is not one is trailing garbage.
                const got = d.streamHeader() catch |e| {
                    if (had_stream and (e == error.BadMagic or e == error.TruncatedInput)) {
                        if (d.opts.ignore_trailing_garbage) {
                            d.phase = .done;
                            continue;
                        }
                        return error.TrailingData;
                    }
                    return e;
                };
                d.phase = if (got) .block_header else .done;
            },
            .block_header => {
                const is_block = try d.blockHeader();
                d.phase = if (is_block) .block_output else .stream_header;
            },
            .block_output => {
                var room = dest.len;
                if (d.opts.max_output) |cap| {
                    // One byte past the cap is enough to notice.
                    const left = cap -| d.total_out;
                    room = @intCast(@min(@as(u64, room), left +| 1));
                }
                const n = try d.unRle(dest[0..room]);
                if (n > 0) {
                    d.total_out += n;
                    if (d.opts.max_output) |cap| if (d.total_out > cap) return error.OutputTooLarge;
                    return n;
                }
                if (d.used != d.nblock + 1 or d.out_len != 0) return error.BadBlockData;
                const got = crc.finalize(d.block_crc);
                if (got != d.stored_block_crc) return error.BlockCrcMismatch;
                d.combined_crc = crc.combine(d.combined_crc, got);
                d.phase = .block_header;
            },
        };
    }
};

/// Decompress every stream of `input`. Caller owns the result.
pub fn decompress(gpa: std.mem.Allocator, input: []const u8, opts: Options) Error![]u8 {
    var in: Reader = .fixed(input);
    var out: Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = decompressStream(gpa, &in, &out.writer, opts) catch |e| switch (e) {
        error.WriteFailed => return error.OutOfMemory,
        else => |x| return x,
    };
    return out.toOwnedSlice() catch error.OutOfMemory;
}

/// Decompress from `in` to `out`; returns the output length. `in` needs a
/// non-empty buffer. `out` is flushed at the end. The decoder reads up to 8
/// bytes ahead, so it should be given the whole of `in`'s stream(s).
pub fn decompressStream(gpa: std.mem.Allocator, in: *Reader, out: *Writer, opts: Options) (Error || error{WriteFailed})!u64 {
    var d = try Decoder.init(gpa, in, opts);
    defer d.deinit();
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = try d.read(&buf);
        if (n == 0) break;
        try out.writeAll(buf[0..n]);
    }
    try out.flush();
    return d.total_out;
}

/// A pull `std.Io.Reader` over the decompressed bytes of the .bz2 stream(s)
/// read from `in`. A failure is `error.ReadFailed` from the reader with the
/// cause in `err`; at the end the reader reports `EndOfStream`.
pub const DecompressReader = struct {
    /// The interface. Its buffer is the one passed to `init` (it may be empty).
    reader: Reader,
    err: ?Error = null,
    dec: Decoder,

    /// `in` must have a non-empty buffer. Allocates the decoder's tables;
    /// the block buffer is allocated when a stream header is read.
    pub fn init(gpa: std.mem.Allocator, in: *Reader, buffer: []u8, opts: Options) error{OutOfMemory}!DecompressReader {
        return .{
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .dec = try .init(gpa, in, opts),
        };
    }

    pub fn deinit(r: *DecompressReader) void {
        r.dec.deinit();
        r.* = undefined;
    }

    fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const self: *DecompressReader = @alignCast(@fieldParentPtr("reader", r));
        if (self.err != null) return error.ReadFailed;
        if (limit == .nothing) return 0;
        var tmp: [4096]u8 = undefined;
        if (w.buffer.len == 0) {
            const want = limit.slice(&tmp);
            const n = self.dec.read(want) catch |e| {
                self.err = e;
                return error.ReadFailed;
            };
            if (n == 0) return error.EndOfStream;
            try w.writeAll(want[0..n]);
            return n;
        }
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = self.dec.read(dest) catch |e| {
            self.err = e;
            return error.ReadFailed;
        };
        if (n == 0) return error.EndOfStream;
        w.advance(n);
        return n;
    }
};
