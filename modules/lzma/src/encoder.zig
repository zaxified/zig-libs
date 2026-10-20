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

pub const Check = xzfmt.Check;
pub const Mode = le.Mode;
pub const MatchFinder = lz.MatchFinder;
/// The LZMA parameters: lc/lp/pb, dictionary size, mode, match finder,
/// `nice_len` and `depth`.
pub const LzmaOptions = le.Options;

/// `lzma_lzma_preset`: the xz presets 0..9, `-e` as `extreme`.
pub fn preset(level: u4, extreme: bool) LzmaOptions {
    std.debug.assert(level <= 9);
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
};

pub const WriteError = Writer.Error || error{OutOfMemory};
pub const InitError = error{ OutOfMemory, InvalidOptions };

const lzma2_header_max = 6;
const lzma2_uncompressed_max: u32 = 1 << 21;

const CheckState = union(Check) {
    none: void,
    crc32: std.hash.Crc32,
    crc64: std.hash.crc.@"CRC-64/XZ",
    sha256: std.crypto.hash.sha2.Sha256,

    fn init(k: Check) CheckState {
        return switch (k) {
            .none => .none,
            .crc32 => .{ .crc32 = std.hash.Crc32.init() },
            .crc64 => .{ .crc64 = std.hash.crc.@"CRC-64/XZ".init() },
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
        errdefer st.mf.deinit(gpa);
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
        gpa.destroy(e.st);
        e.* = undefined;
    }

    /// Compress `data`. Output reaches the writer as the coder produces it.
    pub fn write(e: *Encoder, data: []const u8) WriteError!void {
        const st = e.st;
        std.debug.assert(!st.finished);
        if (data.len == 0) return;
        if (st.format == .xz and !st.block_open) {
            try st.out.writeAll(&blockHeader(st.o.dict_size));
            st.block_open = true;
        }
        st.check.update(data);
        st.in_total += data.len;
        var pos: usize = 0;
        _ = try st.lzEncode(data, &pos, .run);
    }

    /// End the stream (it does not flush the writer).
    pub fn finish(e: *Encoder) WriteError!void {
        const st = e.st;
        std.debug.assert(!st.finished);
        st.finished = true;
        if (st.format == .xz and !st.block_open) {
            return writeIndexAndFooter(st, null);
        }
        var pos: usize = 0;
        const ret = try st.lzEncode("", &pos, .finish);
        std.debug.assert(ret == .stream_end);
        if (st.format != .xz) return;
        // Block padding and check, then the index.
        const csize = st.lz_out_total;
        const pad: usize = @intCast((4 - csize % 4) % 4);
        var tail: [3 + 32]u8 = @splat(0);
        var n: usize = pad;
        switch (st.check) {
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
        try st.out.writeAll(tail[0..n]);
        const unpadded = 12 + csize + xzfmt.checkSize(st.check_kind);
        return writeIndexAndFooter(st, .{ unpadded, st.in_total });
    }

    fn writeIndexAndFooter(st: *State, record: ?[2]u64) WriteError!void {
        var idx: [64]u8 = undefined;
        var n: usize = 0;
        idx[n] = 0;
        n += 1;
        n += putVli(idx[n..], if (record == null) 0 else 1);
        if (record) |r| {
            n += putVli(idx[n..], r[0]);
            n += putVli(idx[n..], r[1]);
        }
        while (n % 4 != 0) : (n += 1) idx[n] = 0;
        std.mem.writeInt(u32, idx[n..][0..4], std.hash.Crc32.hash(idx[0..n]), .little);
        n += 4;
        try st.out.writeAll(idx[0..n]);
        var f: [12]u8 = undefined;
        std.mem.writeInt(u32, f[4..8], @intCast(n / 4 - 1), .little);
        f[8] = 0;
        f[9] = @backingInt(st.check_kind);
        std.mem.writeInt(u32, f[0..4], std.hash.Crc32.hash(f[4..10]), .little);
        f[10] = 'Y';
        f[11] = 'Z';
        try st.out.writeAll(&f);
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

/// The 12-byte block header of a single-LZMA2-filter block with unknown sizes.
fn blockHeader(dict_size: u32) [12]u8 {
    var h: [12]u8 = .{ 0x02, 0x00, 0x21, 0x01, lzma2PropsByte(dict_size), 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, h[8..12], std.hash.Crc32.hash(h[0..8]), .little);
    return h;
}

/// Compress a whole buffer. Caller owns the result.
pub fn compress(gpa: std.mem.Allocator, input: []const u8, format: Format, opts: Options) (InitError || WriteError)![]u8 {
    var out: Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var e = try Encoder.init(gpa, &out.writer, format, opts);
    defer e.deinit();
    try e.write(input);
    try e.finish();
    return out.toOwnedSlice();
}

/// A bound on the compressed size of `n` input bytes (any format, any options).
pub fn compressBound(n: usize) usize {
    return n + n / 1024 + 1024;
}

/// `compress` into the caller's buffer; `error.OutputTooLarge` when it does
/// not fit (`compressBound(input.len)` bytes always do). Returns the length.
pub fn compressInto(gpa: std.mem.Allocator, dest: []u8, input: []const u8, format: Format, opts: Options) (InitError || WriteError || error{OutputTooLarge})!usize {
    var w: Writer = .fixed(dest);
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
    /// output. Null when the output failed.
    err: ?std.mem.Allocator.Error = null,

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
        sw.err = @errorCast(e);
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
