// SPDX-License-Identifier: MIT

//! Encoders: raw LZMA1, the `.lzma` file, raw LZMA2 and the `.xz` container,
//! all through one push `Encoder`. The LZMA2 chunker is a port of liblzma's
//! `lzma2_encoder.c`, the stream and block framing follows
//! `lzma_stream_encoder` (one block, sizes unknown in the header, which is
//! what the `xz` program and Python's `lzma` produce).

const std = @import("std");
const Writer = std.Io.Writer;
const c = @import("common.zig");
const lz = @import("lz_enc.zig");
const le = @import("lzma_enc.zig");
const xzfmt = @import("xzfmt.zig");
const filters = @import("filters.zig");
const crc64 = @import("crc64");

pub const Check = xzfmt.Check;
/// A BCJ or delta filter in front of LZMA2.
pub const Filter = filters.Filter;
pub const Mode = le.Mode;
pub const MatchFinder = lz.MatchFinder;
/// The LZMA parameters: lc/lp/pb, dictionary size, mode, match finder,
/// `nice_len` and `depth`.
pub const LzmaOptions = le.Options;

/// `lzma_lzma_preset`: the xz presets 0..9, `-e` as `extreme`. A level above 9
/// is 9.
pub fn preset(level_in: u4, extreme: bool) LzmaOptions {
    const level = @min(level_in, 9);
    const dict_pow2 = [_]u5{ 18, 20, 21, 22, 22, 23, 23, 24, 25, 26 };
    var o: LzmaOptions = .{ .lc = 3, .lp = 0, .pb = 2, .dict_size = @as(u32, 1) << dict_pow2[level] };
    if (level <= 3) {
        o.mode = .fast;
        o.mf = if (level == 0) .hc3 else .hc4;
        o.nice_len = if (level <= 1) 128 else 273;
        const depths = [_]u32{ 4, 8, 24, 48 };
        o.depth = depths[level];
    } else {
        o.mode = .normal;
        o.mf = .bt4;
        o.nice_len = if (level == 4) 16 else if (level == 5) 32 else 64;
        o.depth = 0;
    }
    if (extreme) {
        o.mode = .normal;
        o.mf = .bt4;
        if (level == 3 or level == 5) {
            o.nice_len = 192;
            o.depth = 0;
        } else {
            o.nice_len = 273;
            o.depth = 512;
        }
    }
    return o;
}

pub const Format = enum {
    /// `.xz`: stream header, one LZMA2 block, index, footer.
    xz,
    /// `.lzma`: 13-byte header (unknown size), LZMA1 with an end marker.
    lzma_alone,
    /// Raw LZMA1 with an end marker (no header; the properties are the caller's).
    lzma1,
    /// Raw LZMA2 chunks with the 0x00 end byte.
    lzma2,
};

pub const Options = struct {
    lzma: LzmaOptions = preset(6, false),
    /// `.xz` only.
    check: Check = .crc64,
    /// `.xz` and raw LZMA2: the filters that run on the data before LZMA2, in
    /// the order of `xz --x86 --lzma2` (at most `Filter.max_chain`). Empty for
    /// `.lzma` and raw LZMA1 (`error.InvalidOptions` otherwise).
    filters: []const Filter = &.{},
    /// `.xz` only: start a new block (an independent LZMA2 stream with a
    /// fresh dictionary) every `block_size` uncompressed bytes, as `xz
    /// --block-size`; 0 is one block for the whole stream. Smaller blocks cost
    /// ratio and allow random access and parallel decoding.
    block_size: u64 = 0,
    /// `compress` and `compressInto` with `.xz`: compress the blocks on this
    /// many threads (0 = one per CPU), as `xz -T`: the bytes are those of `xz
    /// -TN` for any N but 1 (a threaded block header carries the block's
    /// sizes, so they differ from the streaming encoder's, which is `xz
    /// -T1`'s). Without `block_size` the block size is `xz`'s default for `-T`
    /// (`mtBlockSize`); `gpa` must be thread-safe. The streaming `Encoder` and
    /// `StreamWriter` ignore it.
    threads: u32 = 1,
};

/// The block size `xz -T` uses when none is given: three times the
/// dictionary size, at least 1 MiB.
pub fn mtBlockSize(dict_size: u32) u64 {
    return @max(@as(u64, dict_size) * 3, 1 << 20);
}

pub const WriteError = Writer.Error || error{
    OutOfMemory,
    /// `write` or `finish` after `finish` (a second `finish` would emit a
    /// second index and footer).
    AlreadyFinished,
};
pub const InitError = error{ OutOfMemory, InvalidOptions };

const lzma2_header_max = 6;
const lzma2_uncompressed_max: u32 = 1 << 21;

const CheckState = union(Check) {
    none: void,
    crc32: std.hash.Crc32,
    crc64: crc64.Crc64,
    sha256: std.crypto.hash.sha2.Sha256,

    fn init(k: Check) CheckState {
        return switch (k) {
            .none => .none,
            .crc32 => .{ .crc32 = std.hash.Crc32.init() },
            .crc64 => .{ .crc64 = crc64.Crc64.init() },
            .sha256 => .{ .sha256 = std.crypto.hash.sha2.Sha256.init(.{}) },
        };
    }

    fn update(s: *CheckState, b: []const u8) void {
        switch (s.*) {
            .none => {},
            .crc32 => |*h| h.update(b),
            .crc64 => |*h| h.update(b),
            .sha256 => |*h| h.update(b),
        }
    }
};

const Lzma2Seq = enum { init, lzma_encode, lzma_copy, uncompressed_header, uncompressed_copy };

const Lzma2 = struct {
    seq: Lzma2Seq = .init,
    need_properties: bool = true,
    need_state_reset: bool = false,
    need_dictionary_reset: bool = true,
    uncompressed_size: usize = 0,
    compressed_size: usize = 0,
    buf_pos: usize = 0,
    buf: [lzma2_header_max + le.lzma2_chunk_max]u8 = undefined,

    fn headerLzma(l: *Lzma2, o: LzmaOptions) void {
        var pos: usize = undefined;
        if (l.need_properties) {
            pos = 0;
            l.buf[pos] = if (l.need_dictionary_reset) 0x80 + (3 << 5) else 0x80 + (2 << 5);
        } else {
            pos = 1;
            l.buf[pos] = if (l.need_state_reset) 0x80 + (1 << 5) else 0x80;
        }
        l.buf_pos = pos;
        var size = l.uncompressed_size - 1;
        l.buf[pos] += @intCast(size >> 16);
        pos += 1;
        l.buf[pos] = @intCast((size >> 8) & 0xFF);
        l.buf[pos + 1] = @intCast(size & 0xFF);
        pos += 2;
        size = l.compressed_size - 1;
        l.buf[pos] = @intCast(size >> 8);
        l.buf[pos + 1] = @intCast(size & 0xFF);
        pos += 2;
        if (l.need_properties) l.buf[pos] = (c.Lclppb{ .lc = @intCast(o.lc), .lp = @intCast(o.lp), .pb = @intCast(o.pb) }).encode();
        l.need_properties = false;
        l.need_state_reset = false;
        l.need_dictionary_reset = false;
        l.compressed_size += lzma2_header_max;
    }

    fn headerUncompressed(l: *Lzma2) void {
        l.buf[0] = if (l.need_dictionary_reset) 1 else 2;
        l.need_dictionary_reset = false;
        l.buf[1] = @intCast((l.uncompressed_size - 1) >> 8);
        l.buf[2] = @intCast((l.uncompressed_size - 1) & 0xFF);
        l.buf_pos = 0;
    }
};

fn bufcpy(in: []const u8, in_pos: *usize, in_size: usize, out: []u8, out_pos: *usize) void {
    const n = @min(in_size - in_pos.*, out.len - out_pos.*);
    @memcpy(out[out_pos.*..][0..n], in[in_pos.*..][0..n]);
    in_pos.* += n;
    out_pos.* += n;
}

const State = struct {
    gpa: std.mem.Allocator,
    out: *Writer,
    format: Format,
    o: LzmaOptions,
    check_kind: Check,
    check: CheckState,
    mf: lz.Mf,
    coder: le.Coder,
    l2: Lzma2,
    /// xz: the block header is out.
    block_open: bool,
    finished: bool,
    in_total: u64,
    lz_out_total: u64,
    /// Filters before LZMA2: their chain, and the encoder-side options the
    /// next block's window and coder are rebuilt from.
    chain: ?*filters.Chain,
    filter_list: [filters.Filter.max_chain]filters.Filter,
    n_filters: u8,
    lzo: lz.Options,
    block_size: u64,
    in_block: u64,
    block_header_len: u64,
    /// One (unpadded size, uncompressed size) record per finished block.
    records: std.ArrayList([2]u64),
    obuf: [16 * 1024]u8 = undefined,

    // ── LZMA2 ──

    fn lzma2Encode(st: *State, out: []u8, out_pos: *usize) le.Ret {
        const mf = &st.mf;
        const l = &st.l2;
        while (out_pos.* < out.len) switch (l.seq) {
            .init => {
                if (mf.unencoded() == 0) {
                    if (mf.action == .finish) {
                        out[out_pos.*] = 0;
                        out_pos.* += 1;
                    }
                    return if (mf.action == .run) .ok else .stream_end;
                }
                if (l.need_state_reset) st.coder.reset(st.o);
                l.uncompressed_size = 0;
                l.compressed_size = 0;
                l.seq = .lzma_encode;
            },
            .lzma_encode => {
                const left: u32 = lzma2_uncompressed_max - @as(u32, @intCast(l.uncompressed_size));
                const limit: u32 = if (left < mf.match_len_max) 0 else mf.read_pos - mf.read_ahead + left - mf.match_len_max;
                const read_start = mf.read_pos - mf.read_ahead;
                const ret = st.coder.encode(mf, l.buf[lzma2_header_max..][0..le.lzma2_chunk_max], &l.compressed_size, limit);
                l.uncompressed_size += mf.read_pos - mf.read_ahead - read_start;
                if (ret != .stream_end) return .ok;
                if (l.compressed_size >= l.uncompressed_size) {
                    l.uncompressed_size += mf.read_ahead;
                    mf.read_ahead = 0;
                    l.headerUncompressed();
                    l.need_state_reset = true;
                    l.seq = .uncompressed_header;
                    continue;
                }
                l.headerLzma(st.o);
                l.seq = .lzma_copy;
            },
            .lzma_copy => {
                bufcpy(&l.buf, &l.buf_pos, l.compressed_size, out, out_pos);
                if (l.buf_pos != l.compressed_size) return .ok;
                l.seq = .init;
            },
            .uncompressed_header => {
                bufcpy(&l.buf, &l.buf_pos, 3, out, out_pos);
                if (l.buf_pos != 3) return .ok;
                l.seq = .uncompressed_copy;
            },
            .uncompressed_copy => {
                // mf_read: the chunk's bytes are in the window just before read_pos.
                const out_avail = out.len - out_pos.*;
                const copy_size = @min(out_avail, l.uncompressed_size);
                const from = mf.read_pos - l.uncompressed_size;
                @memcpy(out[out_pos.*..][0..copy_size], mf.buffer[from..][0..copy_size]);
                out_pos.* += copy_size;
                l.uncompressed_size -= copy_size;
                if (l.uncompressed_size != 0) return .ok;
                l.seq = .init;
            },
        };
        return .ok;
    }

    fn code(st: *State, out: []u8, out_pos: *usize) le.Ret {
        return switch (st.format) {
            .xz, .lzma2 => st.lzma2Encode(out, out_pos),
            .lzma_alone, .lzma1 => st.coder.encode(&st.mf, out, out_pos, std.math.maxInt(u32)),
        };
    }

    fn flushObuf(st: *State, n: usize) WriteError!void {
        if (n == 0) return;
        try st.out.writeAll(st.obuf[0..n]);
        st.lz_out_total += n;
    }

    /// `lz_encode`: feed `in` through the window to the coder. With
    /// `.finish` it runs until the coder has ended.
    fn lzEncode(st: *State, in: []const u8, in_pos: *usize, action: lz.Action) WriteError!le.Ret {
        var out_pos: usize = 0;
        const mf = &st.mf;
        while (true) {
            if (out_pos == st.obuf.len) {
                try st.flushObuf(out_pos);
                out_pos = 0;
            }
            if (!(in_pos.* < in.len or action != .run)) break;
            if (mf.action == .run and mf.read_pos >= mf.read_limit) _ = mf.fillWindow(in, in_pos, action);
            const ret = st.code(&st.obuf, &out_pos);
            if (ret != .ok) {
                mf.action = .run;
                try st.flushObuf(out_pos);
                return ret;
            }
        }
        try st.flushObuf(out_pos);
        return .ok;
    }

    /// The data through the filter chain (if any) into the coder.
    fn feed(st: *State, data: []const u8, final: bool) WriteError!void {
        var pos: usize = 0;
        if (st.chain) |ch| {
            while (pos < data.len) {
                const m = @min(filters.chunk, data.len - pos);
                @memcpy(ch.input()[0..m], data[pos..][0..m]);
                pos += m;
                const conv = ch.feed(m, false);
                var p: usize = 0;
                _ = try st.lzEncode(conv, &p, .run);
            }
            if (final) {
                const conv = ch.feed(0, true);
                var p: usize = 0;
                _ = try st.lzEncode(conv, &p, .run);
            }
            return;
        }
        _ = try st.lzEncode(data, &pos, .run);
    }

    /// Flush the filter tail and end the LZMA2 / LZMA stream of the current block.
    fn finishCoder(st: *State) WriteError!void {
        if (st.chain != null) try st.feed("", true);
        var pos: usize = 0;
        const ret = try st.lzEncode("", &pos, .finish);
        std.debug.assert(ret == .stream_end);
    }

    /// `.xz`: write the next block's header, with a fresh window, coder and
    /// filter chain for every block after the first.
    fn startBlock(st: *State) WriteError!void {
        if (st.records.items.len != 0) {
            st.mf.deinit(st.gpa);
            st.mf = lz.Mf.init(st.gpa, st.lzo) catch return error.OutOfMemory;
            st.l2.seq = .init;
            st.l2.need_properties = true;
            st.l2.need_state_reset = false;
            st.l2.need_dictionary_reset = true;
            @memset(std.mem.asBytes(&st.coder), 0);
            st.coder.init(st.o, false) catch unreachable; // the options were accepted by `init`
            st.check = CheckState.init(st.check_kind);
            if (st.chain) |ch| ch.init(st.filter_list[0..st.n_filters], true);
        }
        var h: [64]u8 = undefined;
        const n = blockHeader(&h, st.filter_list[0..st.n_filters], st.o.dict_size, null, 0);
        try st.out.writeAll(h[0..n]);
        st.block_header_len = n;
        st.block_open = true;
        st.in_block = 0;
        st.lz_out_total = 0;
    }

    /// `.xz`: end the current block: its stream, padding, check and index record.
    fn endBlock(st: *State) WriteError!void {
        try st.finishCoder();
        const csize = st.lz_out_total;
        var tail: [3 + 32]u8 = undefined;
        const n = blockTail(&st.check, csize, &tail);
        try st.out.writeAll(tail[0..n]);
        try st.records.append(st.gpa, .{ st.block_header_len + csize + xzfmt.checkSize(st.check_kind), st.in_block });
        st.block_open = false;
    }

    fn writeIndexAndFooter(st: *State) WriteError!void {
        try writeIndex(st.out, st.records.items, st.check_kind);
    }
};

fn lzma2PropsByte(dict_size: u32) u8 {
    var d = @max(dict_size, lz.dict_size_min) - 1;
    d |= d >> 2;
    d |= d >> 3;
    d |= d >> 4;
    d |= d >> 8;
    d |= d >> 16;
    if (d == std.math.maxInt(u32)) return 40;
    const i: u32 = 31 - @clz(d + 1);
    const slot = (i + i) + (((d + 1) >> @intCast(i - 1)) & 1);
    return @intCast(slot - 24);
}

pub const Encoder = struct {
    st: *State,

    pub fn init(gpa: std.mem.Allocator, out: *Writer, format: Format, opts: Options) (InitError || Writer.Error)!Encoder {
        const o = opts.lzma;
        if (!o.valid() or o.dict_size < lz.dict_size_min or o.dict_size > lz.dict_size_max) return error.InvalidOptions;
        if (opts.filters.len > filters.Filter.max_chain) return error.InvalidOptions;
        if (opts.filters.len != 0 and format != .xz and format != .lzma2) return error.InvalidOptions;
        if (opts.block_size != 0 and format != .xz) return error.InvalidOptions;
        for (opts.filters) |f| if (!f.valid()) return error.InvalidOptions;
        const st = try gpa.create(State);
        errdefer gpa.destroy(st);
        var lzo = o.lzOptions();
        if (format == .xz or format == .lzma2) {
            if (lzo.before_size + lzo.dict_size < le.lzma2_chunk_max) lzo.before_size = le.lzma2_chunk_max - lzo.dict_size;
        }
        const mf = lz.Mf.init(gpa, lzo) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.OptionsError => error.InvalidOptions,
        };
        // Field by field: the state is large and a struct literal would be a
        // temporary of the same size.
        st.gpa = gpa;
        st.out = out;
        st.format = format;
        st.o = o;
        st.check_kind = opts.check;
        st.check = CheckState.init(opts.check);
        st.mf = mf;
        st.l2.seq = .init;
        st.l2.need_properties = true;
        st.l2.need_state_reset = false;
        st.l2.need_dictionary_reset = true;
        st.block_open = false;
        st.finished = false;
        st.in_total = 0;
        st.lz_out_total = 0;
        st.chain = null;
        st.n_filters = @intCast(opts.filters.len);
        @memcpy(st.filter_list[0..opts.filters.len], opts.filters);
        st.lzo = lzo;
        st.block_size = opts.block_size;
        st.in_block = 0;
        st.block_header_len = 0;
        st.records = .empty;
        errdefer st.mf.deinit(gpa);
        if (opts.filters.len != 0) {
            st.chain = try gpa.create(filters.Chain);
            st.chain.?.init(opts.filters, true);
        }
        errdefer if (st.chain) |ch| gpa.destroy(ch);
        @memset(std.mem.asBytes(&st.coder), 0);
        st.coder.init(o, format == .lzma1 or format == .lzma_alone) catch return error.InvalidOptions;
        switch (format) {
            .xz => try out.writeAll(&(xzfmt.header_magic ++ streamFlags(opts.check))),
            .lzma_alone => {
                var h: [13]u8 = undefined;
                h[0] = (c.Lclppb{ .lc = @intCast(o.lc), .lp = @intCast(o.lp), .pb = @intCast(o.pb) }).encode();
                var d = o.dict_size - 1;
                d |= d >> 2;
                d |= d >> 3;
                d |= d >> 4;
                d |= d >> 8;
                d |= d >> 16;
                if (d != std.math.maxInt(u32)) d += 1;
                std.mem.writeInt(u32, h[1..5], d, .little);
                @memset(h[5..13], 0xFF);
                try out.writeAll(&h);
            },
            else => {},
        }
        return .{ .st = st };
    }

    fn streamFlags(k: Check) [6]u8 {
        const f: [2]u8 = .{ 0, @backingInt(k) };
        var b: [6]u8 = undefined;
        b[0..2].* = f;
        std.mem.writeInt(u32, b[2..6], std.hash.Crc32.hash(&f), .little);
        return b;
    }

    pub fn deinit(e: *Encoder) void {
        const gpa = e.st.gpa;
        e.st.mf.deinit(gpa);
        if (e.st.chain) |ch| gpa.destroy(ch);
        e.st.records.deinit(gpa);
        gpa.destroy(e.st);
        e.* = undefined;
    }

    /// Compress `data`. Output reaches the writer as the coder produces it.
    pub fn write(e: *Encoder, data: []const u8) WriteError!void {
        const st = e.st;
        if (st.finished) return error.AlreadyFinished;
        var rest = data;
        while (rest.len != 0) {
            var take = rest.len;
            if (st.format == .xz) {
                if (st.block_open and st.block_size != 0 and st.in_block == st.block_size) try st.endBlock();
                if (!st.block_open) try st.startBlock();
                if (st.block_size != 0) take = @intCast(@min(@as(u64, take), st.block_size - st.in_block));
            }
            const piece = rest[0..take];
            rest = rest[take..];
            st.check.update(piece);
            st.in_total += piece.len;
            st.in_block += piece.len;
            try st.feed(piece, false);
        }
    }

    /// End the stream (it does not flush the writer).
    pub fn finish(e: *Encoder) WriteError!void {
        const st = e.st;
        if (st.finished) return error.AlreadyFinished;
        st.finished = true;
        if (st.format == .xz) {
            if (st.block_open) try st.endBlock();
            return st.writeIndexAndFooter();
        }
        try st.finishCoder();
    }
};

fn putVli(buf: []u8, v_in: u64) usize {
    var v = v_in;
    var i: usize = 0;
    while (v >= 0x80) : (i += 1) {
        buf[i] = @as(u8, @truncate(v)) | 0x80;
        v >>= 7;
    }
    buf[i] = @truncate(v);
    return i + 1;
}

fn vliLen(v: u64) usize {
    var b: [10]u8 = undefined;
    return putVli(&b, v);
}

/// liblzma's bound on the LZMA2 stream of `n` uncompressed bytes (stored
/// chunks of up to 64 KiB, three header bytes each, and the end byte).
fn lzma2Bound(n: u64) u64 {
    return n + 3 * ((n + 65535) / 65536) + 1;
}

/// The block header of a block with the given filters and an LZMA2 filter.
/// `sizes` are the compressed and uncompressed sizes when known: a threaded
/// encoder writes the header after the block (the streaming one cannot, and
/// writes none). Like liblzma's, such a header is sized for a full block of
/// `block_size` bytes (the widths of the bound on its compressed size and of
/// its uncompressed size) and the real, possibly shorter, numbers are
/// zero-padded to it. Returns the length (at most 64).
fn blockHeader(out: *[64]u8, fl: []const Filter, dict_size: u32, sizes: ?[2]u64, block_size: u64) usize {
    var filt: usize = 3;
    for (fl) |f| {
        var p: [4]u8 = undefined;
        filt += 2 + f.props(&p);
    }
    const reserved: usize = if (sizes != null) vliLen(lzma2Bound(block_size)) + vliLen(block_size) else 0;
    const total = (2 + reserved + filt + 4 + 3) & ~@as(usize, 3);
    @memset(out[0..total], 0);
    var n: usize = 2;
    out[1] = @intCast(fl.len); // (filters + 1) - 1
    if (sizes) |sz| {
        out[1] |= 0xC0;
        n += putVli(out[n..], sz[0]);
        n += putVli(out[n..], sz[1]);
    }
    for (fl) |f| {
        var p: [4]u8 = undefined;
        const pl = f.props(&p);
        out[n] = f.id();
        out[n + 1] = @intCast(pl);
        @memcpy(out[n + 2 ..][0..pl], p[0..pl]);
        n += 2 + pl;
    }
    out[n] = 0x21;
    out[n + 1] = 1;
    out[n + 2] = lzma2PropsByte(dict_size);
    out[0] = @intCast(total / 4 - 1);
    std.mem.writeInt(u32, out[total - 4 ..][0..4], std.hash.Crc32.hash(out[0 .. total - 4]), .little);
    return total;
}

/// Everything after the block header: the LZMA2 stream's padding to a multiple
/// of four and the check; returns the length written into `tail`.
fn blockTail(check: *const CheckState, csize: u64, tail: *[3 + 32]u8) usize {
    const pad: usize = @intCast((4 - csize % 4) % 4);
    @memset(tail[0..pad], 0);
    var n: usize = pad;
    switch (check.*) {
        .none => {},
        .crc32 => |h| {
            std.mem.writeInt(u32, tail[n..][0..4], h.final(), .little);
            n += 4;
        },
        .crc64 => |h| {
            std.mem.writeInt(u64, tail[n..][0..8], h.final(), .little);
            n += 8;
        },
        .sha256 => |h| {
            var hh = h;
            hh.final(tail[n..][0..32]);
            n += 32;
        },
    }
    return n;
}

/// Compress a whole buffer. Caller owns the result.
pub fn compress(gpa: std.mem.Allocator, input: []const u8, format: Format, opts: Options) (InitError || WriteError)![]u8 {
    if (format == .xz and opts.threads != 1) {
        const bs = if (opts.block_size != 0) opts.block_size else mtBlockSize(opts.lzma.dict_size);
        return compressParallel(gpa, input, opts, bs);
    }
    var out: Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var e = try Encoder.init(gpa, &out.writer, format, opts);
    defer e.deinit();
    try e.write(input);
    try e.finish();
    return out.toOwnedSlice();
}

const Job = struct {
    gpa: std.mem.Allocator,
    input: []const u8,
    opts: Options,
    block_size: u64,
    next: std.atomic.Value(usize) = .init(0),
    results: []Result,
};

const Result = struct {
    /// The block's LZMA2 stream (header excluded).
    body: []u8 = &.{},
    tail: [3 + 32]u8 = undefined,
    tail_len: usize = 0,
    err: ?(InitError || WriteError) = null,
};

fn worker(job: *Job) void {
    while (true) {
        const i = job.next.fetchAdd(1, .monotonic);
        if (i >= job.results.len) return;
        const r = &job.results[i];
        const start: usize = @intCast(@as(u64, i) * job.block_size);
        const end: usize = @intCast(@min(@as(u64, job.input.len), (@as(u64, i) + 1) * job.block_size));
        compressBlock(job, r, job.input[start..end]) catch |e| {
            r.err = e;
        };
    }
}

fn compressBlock(job: *Job, r: *Result, data: []const u8) (InitError || WriteError)!void {
    var out: Writer.Allocating = .init(job.gpa);
    errdefer out.deinit();
    var o = job.opts;
    o.block_size = 0;
    var e = try Encoder.init(job.gpa, &out.writer, .lzma2, o);
    defer e.deinit();
    try e.write(data);
    try e.finish();
    r.body = try out.toOwnedSlice();
    r.tail_len = blockTail(&e.st.check, r.body.len, &r.tail);
}

fn compressParallel(gpa: std.mem.Allocator, input: []const u8, opts: Options, block_size: u64) (InitError || WriteError)![]u8 {
    const o = opts.lzma;
    if (!o.valid() or o.dict_size < lz.dict_size_min or o.dict_size > lz.dict_size_max) return error.InvalidOptions;
    if (opts.filters.len > filters.Filter.max_chain) return error.InvalidOptions;
    for (opts.filters) |f| if (!f.valid()) return error.InvalidOptions;
    const n_blocks: usize = @intCast((@as(u64, input.len) + block_size - 1) / block_size);
    const results = try gpa.alloc(Result, n_blocks);
    defer gpa.free(results);
    for (results) |*r| r.* = .{};
    defer for (results) |r| gpa.free(r.body);
    var job: Job = .{ .gpa = gpa, .input = input, .opts = opts, .block_size = block_size, .results = results };
    const want: usize = if (opts.threads == 0) std.Thread.getCpuCount() catch 1 else opts.threads;
    const n_threads = @max(1, @min(want, n_blocks));
    const handles = try gpa.alloc(?std.Thread, n_threads - 1);
    defer gpa.free(handles);
    for (handles) |*h| h.* = std.Thread.spawn(.{}, worker, .{&job}) catch null; // a failed spawn: the others do its share
    worker(&job);
    for (handles) |h| if (h) |t| t.join();
    for (results) |r| if (r.err) |e| return e;

    var out: Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll(&(xzfmt.header_magic ++ Encoder.streamFlags(opts.check)));
    var records: std.ArrayList([2]u64) = .empty;
    defer records.deinit(gpa);
    for (results, 0..) |r, i| {
        const unc = @min(block_size, input.len - i * block_size);
        var hdr: [64]u8 = undefined;
        const hl = blockHeader(&hdr, opts.filters, o.dict_size, .{ r.body.len, unc }, block_size);
        try w.writeAll(hdr[0..hl]);
        try w.writeAll(r.body);
        try w.writeAll(r.tail[0..r.tail_len]);
        try records.append(gpa, .{ hl + r.body.len + xzfmt.checkSize(opts.check), unc });
    }
    try writeIndex(w, records.items, opts.check);
    return out.toOwnedSlice();
}

fn writeIndex(w: *Writer, records: []const [2]u64, check: Check) Writer.Error!void {
    var crc = std.hash.Crc32.init();
    var n: usize = 0;
    var b: [10]u8 = undefined;
    b[0] = 0;
    try w.writeAll(b[0..1]);
    crc.update(b[0..1]);
    n += 1;
    const count = putVli(&b, records.len);
    try w.writeAll(b[0..count]);
    crc.update(b[0..count]);
    n += count;
    for (records) |r| for (r) |v| {
        const l = putVli(&b, v);
        try w.writeAll(b[0..l]);
        crc.update(b[0..l]);
        n += l;
    };
    const zeros = [3]u8{ 0, 0, 0 };
    const pad = (4 - n % 4) % 4;
    try w.writeAll(zeros[0..pad]);
    crc.update(zeros[0..pad]);
    n += pad;
    var c4: [4]u8 = undefined;
    std.mem.writeInt(u32, &c4, crc.final(), .little);
    try w.writeAll(&c4);
    n += 4;
    var f: [12]u8 = undefined;
    std.mem.writeInt(u32, f[4..8], @intCast(n / 4 - 1), .little);
    f[8] = 0;
    f[9] = @backingInt(check);
    std.mem.writeInt(u32, f[0..4], std.hash.Crc32.hash(f[4..10]), .little);
    f[10] = 'Y';
    f[11] = 'Z';
    try w.writeAll(&f);
}

/// A bound on the compressed size of `n` input bytes (any format, any options).
/// Raw LZMA1 and `.lzma` have no stored mode: incompressible input grows by
/// ~1.4 % (measured on random bytes, liblzma's encoder and ours being
/// byte-identical), so the bound allows 1/32; `.xz`/LZMA2 fall back to stored
/// chunks and stay far below it. A `.xz` with `block_size` has up to 128
/// bytes of block header, padding, check and index record more per block.
pub fn compressBound(n: usize) usize {
    return n +| n / 32 +| 1024;
}

/// `compress` into the caller's buffer; `error.OutputTooLarge` when it does
/// not fit (`compressBound(input.len)` bytes always do). Returns the length.
pub fn compressInto(gpa: std.mem.Allocator, dest: []u8, input: []const u8, format: Format, opts: Options) (InitError || WriteError || error{OutputTooLarge})!usize {
    var w: Writer = .fixed(dest);
    if (format == .xz and opts.threads != 1) {
        const all = try compress(gpa, input, format, opts);
        defer gpa.free(all);
        if (all.len > dest.len) return error.OutputTooLarge;
        @memcpy(dest[0..all.len], all);
        return all.len;
    }
    var e = try Encoder.init(gpa, &w, format, opts);
    defer e.deinit();
    e.write(input) catch |err| return if (err == error.WriteFailed) error.OutputTooLarge else err;
    e.finish() catch |err| return if (err == error.WriteFailed) error.OutputTooLarge else err;
    return w.end;
}

/// A `std.Io.Writer` that compresses what is written to it.
pub const StreamWriter = struct {
    /// The interface. Its buffer is the one passed to `init`.
    writer: Writer,
    enc: Encoder,
    /// Why the last `error.WriteFailed` came from here rather than from the
    /// output: `OutOfMemory`, or `AlreadyFinished` for a `finish` after
    /// `finish` and for a write after a failed `finish`. Null when the output
    /// failed.
    err: ?(std.mem.Allocator.Error || error{AlreadyFinished}) = null,

    const vtable: Writer.VTable = .{ .drain = drain };

    pub fn init(gpa: std.mem.Allocator, output: *Writer, buffer: []u8, format: Format, opts: Options) (InitError || Writer.Error)!StreamWriter {
        return .{
            .writer = .{ .buffer = buffer, .vtable = &vtable },
            .enc = try .init(gpa, output, format, opts),
        };
    }

    pub fn deinit(sw: *StreamWriter) void {
        sw.enc.deinit();
        sw.* = undefined;
    }

    /// The buffered bytes, the last chunk and the trailer; then the writer
    /// accepts nothing more.
    pub fn finish(sw: *StreamWriter) Writer.Error!void {
        const w = &sw.writer;
        try sw.feed(w.buffer[0..w.end]);
        w.end = 0;
        sw.enc.finish() catch |e| return sw.fail(e);
        w.* = .failing;
    }

    fn fail(sw: *StreamWriter, e: WriteError) Writer.Error {
        if (e == error.WriteFailed) return error.WriteFailed;
        sw.err = @errorCast(e); // e is never WriteFailed here, and the field type holds the rest
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
