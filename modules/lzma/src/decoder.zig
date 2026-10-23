// SPDX-License-Identifier: MIT

//! Decoders: raw LZMA1, the `.lzma` ("alone") file, raw LZMA2, and the `.xz`
//! container, all behind one pull `Decoder`.

const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const c = @import("common.zig");
const dec = @import("lzma_dec.zig");
const xzfmt = @import("xzfmt.zig");

pub const Error = error{
    /// The `.xz` stream magic is wrong.
    BadMagic,
    /// A stream or block header is malformed (flags, sizes, padding, CRC).
    BadHeader,
    /// A stream footer or the stream padding is malformed.
    BadFooter,
    /// The index does not describe the blocks that were decoded.
    BadIndex,
    /// A filter other than LZMA2 (BCJ, delta, ...) or an unknown filter ID.
    UnsupportedFilter,
    /// An integrity-check type other than none, CRC32, CRC64, SHA-256.
    UnsupportedCheck,
    /// The stream asks for a dictionary larger than `Options.max_dict`.
    DictTooLarge,
    /// The compressed data is invalid.
    CorruptData,
    /// A CRC or SHA-256 over the uncompressed data does not match.
    CheckMismatch,
    /// The input ended before the stream did.
    TruncatedInput,
    /// Bytes follow the end of the stream (and `ignore_trailing_garbage` is off).
    TrailingData,
    /// More than `Options.max_output` bytes would be produced.
    OutputTooLarge,
    /// The input reader failed; its own diagnostics say why.
    ReadFailed,
    OutOfMemory,
};

pub const Options = struct {
    /// The largest dictionary a stream may ask for, in bytes. The decoder
    /// allocates it (rounded up to 16, at most the output the stream can have)
    /// before decoding, so this is the memory guard against a hostile header.
    /// xz's preset 9 uses 64 MiB.
    max_dict: u32 = 64 << 20,
    /// The most output bytes; one byte over is `error.OutputTooLarge`.
    max_output: u64 = std.math.maxInt(u64),
    /// `.xz` only: read concatenated streams (and the zero padding between
    /// them) to the end of the input; if false, stop after the first stream.
    multi_stream: bool = true,
    /// `.xz` and `.lzma`: ignore what follows the stream (or, for `.xz`, what
    /// follows the last stream with a valid header) instead of reporting
    /// `error.TrailingData`.
    ignore_trailing_garbage: bool = false,
};

/// The five property bytes of an LZMA1 stream: lc/lp/pb and the dictionary
/// size. The first bytes of a `.lzma` file, and what ZIP method 14 carries
/// after its 4-byte header.
pub const Lzma1Props = struct {
    lc: u8,
    lp: u8,
    pb: u8,
    dict_size: u32,

    pub const Invalid = error{BadProperties};

    pub fn fromBytes(b: *const [5]u8) Invalid!Lzma1Props {
        const p = c.Lclppb.decode(b[0]) orelse return error.BadProperties;
        return .{ .lc = p.lc, .lp = p.lp, .pb = p.pb, .dict_size = std.mem.readInt(u32, b[1..5], .little) };
    }

    pub fn toBytes(p: Lzma1Props) [5]u8 {
        var b: [5]u8 = undefined;
        b[0] = (c.Lclppb{ .lc = p.lc, .lp = p.lp, .pb = p.pb }).encode();
        std.mem.writeInt(u32, b[1..5], p.dict_size, .little);
        return b;
    }
};

pub const Format = union(enum) {
    /// A `.xz` file: stream header, blocks (LZMA2 only), index, footer.
    xz,
    /// A `.lzma` file: 13-byte header (properties, dictionary size,
    /// uncompressed size or "unknown"), one LZMA1 stream.
    lzma_alone,
    /// Raw LZMA1 with the properties given out of band (ZIP method 14).
    lzma1: Lzma1,
    /// Raw LZMA2 chunks up to and including the 0x00 end byte.
    lzma2: struct { dict_size: u32 },

    pub const Lzma1 = struct {
        props: Lzma1Props,
        /// The uncompressed size when known (ZIP gives it); null means the
        /// stream must end with an end-of-payload marker.
        uncompressed_size: ?u64 = null,
        /// With a known size, accept an end marker after the last byte too
        /// (ZIP general-purpose bit 1 sets one).
        allow_eopm: bool = true,
    };
};

const Phase = enum { start, segment, lzma2_control, xz_block, done };

const CheckState = union(xzfmt.Check) {
    none: void,
    crc32: std.hash.Crc32,
    crc64: std.hash.crc.@"CRC-64/XZ",
    sha256: std.crypto.hash.sha2.Sha256,

    fn init(k: xzfmt.Check) CheckState {
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

pub const Decoder = struct {
    gpa: std.mem.Allocator,
    in: *Reader,
    opts: Options,
    format: Format,
    lz: *dec.Lzma,
    dict: dec.Dict = .{ .buf = &.{} },
    phase: Phase = .start,
    failed: ?Error = null,
    /// Output produced so far.
    total_out: u64 = 0,

    // The current segment: an LZMA run or an uncompressed LZMA2 chunk.
    seg_copy: bool = false,
    seg_known: bool = false,
    seg_left: u64 = 0,
    budget: u64 = std.math.maxInt(u64),
    eopm_allowed: bool = false,
    eopm_seen: bool = false,

    // LZMA2.
    props: c.Lclppb = .{ .lc = 0, .lp = 0, .pb = 0 },
    need_dict_reset: bool = true,
    need_props: bool = true,
    lzma2_dict_size: u32 = 0,

    // .xz.
    stream_check: xzfmt.Check = .none,
    check: CheckState = .none,
    streams: u64 = 0,
    block: xzfmt.BlockHeader = undefined,
    block_in: u64 = 0,
    block_out: u64 = 0,
    index: xzfmt.IndexHash = .{},
    stream_started: bool = false,

    /// `in` needs a non-empty buffer (an empty one cannot take a byte).
    pub fn init(gpa: std.mem.Allocator, in: *Reader, format: Format, opts: Options) error{OutOfMemory}!Decoder {
        const lz = try gpa.create(dec.Lzma);
        return .{ .gpa = gpa, .in = in, .opts = opts, .format = format, .lz = lz };
    }

    pub fn deinit(d: *Decoder) void {
        if (d.dict.buf.len != 0) d.gpa.free(d.dict.buf);
        d.gpa.destroy(d.lz);
        d.* = undefined;
    }

    /// Up to `dest.len` decompressed bytes; 0 at the end of the stream (and,
    /// trivially, for an empty `dest` — pass a non-empty one). After an error
    /// the decoder stays failed.
    pub fn read(d: *Decoder, dest: []u8) Error!usize {
        if (d.failed) |e| return e;
        if (dest.len == 0) return 0;
        return d.readInner(dest) catch |e| {
            d.failed = e;
            return e;
        };
    }

    // ── input helpers ───────────────────────────────────────────────────

    fn inFail(e: Reader.Error) Error {
        return switch (e) {
            error.EndOfStream => error.TruncatedInput,
            error.ReadFailed => error.ReadFailed,
        };
    }

    fn readBytes(d: *Decoder, buf: []u8) Error!void {
        d.in.readSliceAll(buf) catch |e| return inFail(e);
    }

    fn readByte(d: *Decoder) Error!u8 {
        return d.in.takeByte() catch |e| return inFail(e);
    }

    fn lzErr(e: dec.RunError) Error {
        return switch (e) {
            error.CorruptData => error.CorruptData,
            error.TruncatedInput => error.TruncatedInput,
            error.ReadFailed => error.ReadFailed,
        };
    }

    // ── dictionary / segment setup ──────────────────────────────────────

    /// (Re)allocate the ring for a dictionary of `dict_size` bytes when the
    /// stream can produce at most `known` bytes.
    fn setupDict(d: *Decoder, dict_size: u32, known: ?u64) Error!void {
        var size: u64 = @max(dict_size, 4096);
        size = (size + 15) & ~@as(u64, 15);
        var cap: u64 = std.math.maxInt(u64);
        if (known) |k| cap = @min(cap, k);
        if (d.opts.max_output != std.math.maxInt(u64)) cap = @min(cap, d.opts.max_output +| 1);
        // A ring that can wrap is a multiple of 16; one that cannot is only
        // as large as the output.
        if (cap < size) size = @max(cap, 1);
        // The cap is on what is allocated: a 1 KB entry written with a 1.5 GiB
        // dictionary needs a 1 KB ring (liblzma accepts it too).
        if (size > d.opts.max_dict) return error.DictTooLarge;
        const n: usize = std.math.cast(usize, size) orelse return error.OutOfMemory;
        if (d.dict.buf.len != n) {
            if (d.dict.buf.len != 0) d.gpa.free(d.dict.buf);
            d.dict.buf = &.{};
            d.dict.buf = d.gpa.alloc(u8, n) catch return error.OutOfMemory;
        }
        d.dict.reset();
    }

    fn startLzma1(d: *Decoder, f: Format.Lzma1) Error!void {
        // `Lzma1Props` is a public struct: props built by hand bypass
        // `fromBytes`'s check, and an lc/lp/pb out of range would index past
        // the literal tables.
        if (@as(u16, f.props.lc) + f.props.lp > 4 or f.props.pb > 4) return error.BadHeader;
        const p = c.Lclppb{ .lc = f.props.lc, .lp = f.props.lp, .pb = f.props.pb };
        try d.setupDict(f.props.dict_size, f.uncompressed_size);
        d.lz.reset(p);
        d.budget = std.math.maxInt(u64);
        d.lz.initRc(d.in, &d.budget) catch |e| return lzErr(e);
        d.seg_copy = false;
        d.seg_known = f.uncompressed_size != null;
        d.seg_left = f.uncompressed_size orelse 0;
        d.eopm_allowed = f.allow_eopm;
        d.eopm_seen = false;
        d.phase = .segment;
    }

    // ── the output loop ─────────────────────────────────────────────────

    fn readInner(d: *Decoder, dest: []u8) Error!usize {
        while (true) switch (d.phase) {
            .done => return 0,
            .start => switch (d.format) {
                .lzma1 => |f| try d.startLzma1(f),
                .lzma_alone => {
                    var hdr: [13]u8 = undefined;
                    try d.readBytes(&hdr);
                    const props = Lzma1Props.fromBytes(hdr[0..5]) catch return error.BadHeader;
                    const size = std.mem.readInt(u64, hdr[5..13], .little);
                    try d.startLzma1(.{
                        .props = props,
                        .uncompressed_size = if (size == std.math.maxInt(u64)) null else size,
                        .allow_eopm = true,
                    });
                },
                .lzma2 => |f| {
                    try d.setupDict(f.dict_size, null);
                    d.lzma2_dict_size = f.dict_size;
                    d.phase = .lzma2_control;
                },
                .xz => try d.xzStreamHeader(),
            },
            .segment => {
                if (d.eopm_seen or (d.seg_known and d.seg_left == 0)) {
                    try d.segmentEnd();
                    continue;
                }
                const n = try d.produce(dest);
                if (n != 0) return n;
            },
            .lzma2_control => try d.lzma2Control(),
            .xz_block => try d.xzBlockStart(),
        };
    }

    /// One step of the current segment into `dest`; 0 when it only changed
    /// state (end marker seen).
    fn produce(d: *Decoder, dest: []u8) Error!usize {
        var want: usize = @min(dest.len, d.dict.buf.len - d.dict.pos);
        if (d.seg_known) want = @intCast(@min(@as(u64, want), d.seg_left));
        if (d.opts.max_output != std.math.maxInt(u64)) {
            const room = d.opts.max_output +| 1 - d.total_out;
            want = @intCast(@min(@as(u64, want), room));
        }
        if (want == 0) return if (d.total_out > d.opts.max_output or d.dict.pos < d.dict.buf.len) error.OutputTooLarge else error.CorruptData;
        const start = d.dict.pos;
        if (d.seg_copy) {
            const slot = d.dict.buf[start..][0..want];
            d.readBytes(slot) catch |e| return e;
            d.budget -= want;
            d.dict.pos += want;
        } else {
            const eopm_ok = d.eopm_allowed and !d.seg_known;
            const r = d.lz.run(&d.dict, d.in, &d.budget, want, eopm_ok) catch |e| return lzErr(e);
            if (r == .eopm) d.eopm_seen = true;
        }
        const n = d.dict.pos - start;
        if (n != 0) {
            @memcpy(dest[0..n], d.dict.buf[start..][0..n]);
            // Only a ring whose size is a multiple of 16 may wrap: the position
            // bits of the stream are `pos & 15`. Any other ring is as large as
            // the whole output and never needs to.
            if (d.dict.pos == d.dict.buf.len and d.dict.buf.len % 16 == 0) d.dict.wrap();
            if (d.seg_known) d.seg_left -= n;
            d.total_out += n;
            d.block_out += n;
            if (d.phaseIsXz()) d.check.update(dest[0..n]);
            if (d.total_out > d.opts.max_output) return error.OutputTooLarge;
        }
        return n;
    }

    fn phaseIsXz(d: *const Decoder) bool {
        return d.format == .xz;
    }

    /// The segment has produced all its bytes (or met its end marker).
    fn segmentEnd(d: *Decoder) Error!void {
        if (d.seg_copy) {
            d.phase = .lzma2_control;
            return;
        }
        const lz = d.lz;
        switch (d.format) {
            .lzma1, .lzma_alone => {
                if (d.eopm_seen) {
                    if (!(lz.finished(d.in, &d.budget) catch |e| return lzErr(e))) return error.CorruptData;
                } else {
                    // The known size is reached.
                    if (lz.pending() != 0) return error.CorruptData;
                    if (!(lz.finished(d.in, &d.budget) catch |e| return lzErr(e))) {
                        if (!d.eopm_allowed) return error.CorruptData;
                        lz.endMarker(&d.dict, d.in, &d.budget) catch |e| return lzErr(e);
                        if (!(lz.finished(d.in, &d.budget) catch |e| return lzErr(e))) return error.CorruptData;
                    }
                }
                d.phase = .done;
                if (d.format == .lzma_alone and !d.opts.ignore_trailing_garbage) {
                    _ = d.in.peekByte() catch |e| switch (e) {
                        error.EndOfStream => return,
                        error.ReadFailed => return error.ReadFailed,
                    };
                    return error.TrailingData;
                }
            },
            else => {
                // An LZMA2 chunk: exactly consumed, clean range coder.
                if (lz.pending() != 0) return error.CorruptData;
                if (!(lz.finished(d.in, &d.budget) catch |e| return lzErr(e))) return error.CorruptData;
                if (d.budget != 0) return error.CorruptData;
                d.phase = .lzma2_control;
            },
        }
    }

    // ── LZMA2 ───────────────────────────────────────────────────────────

    fn lzma2Control(d: *Decoder) Error!void {
        const ctl = try d.readByte();
        d.block_in += 1;
        if (ctl == 0) {
            switch (d.format) {
                .xz => try d.xzBlockEnd(),
                else => d.phase = .done,
            }
            return;
        }
        if (ctl >= 0xE0 or ctl == 1) {
            d.need_props = true;
            d.need_dict_reset = true;
        } else if (d.need_dict_reset) return error.CorruptData;

        if (ctl >= 0x80) {
            var sz: [4]u8 = undefined;
            try d.readBytes(sz[0..4]);
            d.block_in += 4;
            const usize_: u64 = (@as(u64, ctl & 0x1F) << 16) + (@as(u64, sz[0]) << 8) + sz[1] + 1;
            const csize: u64 = (@as(u64, sz[2]) << 8) + sz[3] + 1;
            if (ctl >= 0xC0) {
                const pb = try d.readByte();
                d.block_in += 1;
                d.props = c.Lclppb.decode(pb) orelse return error.CorruptData;
                d.need_props = false;
                d.lz.reset(d.props);
            } else if (d.need_props) {
                return error.CorruptData;
            } else if (ctl >= 0xA0) {
                d.lz.reset(d.props);
            }
            if (d.need_dict_reset) {
                d.need_dict_reset = false;
                d.dict.reset();
            }
            d.block_in += csize;
            d.budget = csize;
            d.lz.initRc(d.in, &d.budget) catch |e| return lzErr(e);
            d.seg_copy = false;
            d.seg_known = true;
            d.seg_left = usize_;
            d.eopm_allowed = false;
            d.eopm_seen = false;
            d.phase = .segment;
        } else {
            if (ctl > 2) return error.CorruptData;
            var sz: [2]u8 = undefined;
            try d.readBytes(&sz);
            d.block_in += 2;
            const n: u64 = (@as(u64, sz[0]) << 8) + sz[1] + 1;
            if (d.need_dict_reset) {
                d.need_dict_reset = false;
                d.dict.reset();
            }
            d.block_in += n;
            d.budget = n;
            d.seg_copy = true;
            d.seg_known = true;
            d.seg_left = n;
            d.phase = .segment;
        }
    }

    // ── .xz ─────────────────────────────────────────────────────────────

    fn xzStreamHeader(d: *Decoder) Error!void {
        var h: [12]u8 = undefined;
        if (d.streams == 0) {
            try d.readBytes(h[0..6]);
            if (!std.mem.eql(u8, h[0..6], &xzfmt.header_magic)) return error.BadMagic;
        } else {
            // After a stream: another one, or garbage (one byte at a time,
            // so that any input buffer size works).
            for (xzfmt.header_magic, 0..) |m, i| {
                const b = d.in.takeByte() catch |e| switch (e) {
                    error.ReadFailed => return error.ReadFailed,
                    error.EndOfStream => return d.xzGarbage(),
                };
                if (b != m) return d.xzGarbage();
                h[i] = b;
            }
        }
        try d.readBytes(h[6..12]);
        d.stream_check = try xzfmt.parseStreamFlags(h[6..8], h[8..12]);
        d.index = .{};
        d.streams += 1;
        d.phase = .xz_block;
    }

    fn xzGarbage(d: *Decoder) Error!void {
        if (!d.opts.ignore_trailing_garbage) return error.TrailingData;
        d.phase = .done;
    }

    fn xzBlockStart(d: *Decoder) Error!void {
        const b0 = try d.readByte();
        if (b0 == 0) return d.xzIndexAndFooter();
        const size = (@as(usize, b0) + 1) * 4;
        var buf: [1024]u8 = undefined;
        buf[0] = b0;
        try d.readBytes(buf[1..size]);
        d.block = try xzfmt.parseBlockHeader(buf[0..size]);
        d.block.header_size = @intCast(size);
        d.block_in = 0;
        d.block_out = 0;
        d.check = CheckState.init(d.stream_check);
        d.lzma2_dict_size = d.block.dict_size;
        try d.setupDict(d.block.dict_size, d.block.uncompressed_size);
        d.need_dict_reset = true;
        d.need_props = true;
        d.phase = .lzma2_control;
    }

    fn xzBlockEnd(d: *Decoder) Error!void {
        const b = &d.block;
        if (b.compressed_size) |s| if (s != d.block_in) return error.CorruptData;
        if (b.uncompressed_size) |s| if (s != d.block_out) return error.CorruptData;
        // Block padding.
        const pad: usize = @intCast((4 - d.block_in % 4) % 4);
        var z: [3]u8 = undefined;
        try d.readBytes(z[0..pad]);
        for (z[0..pad]) |x| if (x != 0) return error.CorruptData;
        // The check.
        const csize = xzfmt.checkSize(d.stream_check);
        var stored: [32]u8 = undefined;
        try d.readBytes(stored[0..csize]);
        switch (d.check) {
            .none => {},
            .crc32 => |h| {
                if (std.mem.readInt(u32, stored[0..4], .little) != h.final()) return error.CheckMismatch;
            },
            .crc64 => |h| {
                if (std.mem.readInt(u64, stored[0..8], .little) != h.final()) return error.CheckMismatch;
            },
            .sha256 => |h| {
                var hh = h;
                var out: [32]u8 = undefined;
                hh.final(&out);
                if (!std.mem.eql(u8, &out, stored[0..32])) return error.CheckMismatch;
            },
        }
        const unpadded = @as(u64, b.header_size) + d.block_in + csize;
        d.index.add(unpadded, d.block_out) catch return error.CorruptData;
        d.phase = .xz_block;
    }

    /// The 0x00 index indicator was just read.
    fn xzIndexAndFooter(d: *Decoder) Error!void {
        var crc = std.hash.Crc32.init();
        crc.update(&.{0});
        var used: u64 = 1;
        const n = try d.vli(&crc, &used);
        if (n != d.index.count) return error.BadIndex;
        var want = xzfmt.IndexHash{};
        for (0..n) |_| {
            const unpadded = try d.vli(&crc, &used);
            const unc = try d.vli(&crc, &used);
            if (unpadded < 5 or unpadded > xzfmt.vli_max) return error.BadIndex;
            want.add(unpadded, unc) catch return error.BadIndex;
        }
        if (want.crc.final() != d.index.crc.final() or want.total != d.index.total) return error.BadIndex;
        const pad: usize = @intCast((4 - used % 4) % 4);
        var z: [3]u8 = undefined;
        try d.readBytes(z[0..pad]);
        for (z[0..pad]) |x| if (x != 0) return error.BadIndex;
        crc.update(z[0..pad]);
        used += pad;
        var stored: [4]u8 = undefined;
        try d.readBytes(&stored);
        if (std.mem.readInt(u32, &stored, .little) != crc.final()) return error.BadIndex;
        used += 4;

        var f: [12]u8 = undefined;
        try d.readBytes(&f);
        const footer = xzfmt.parseFooter(&f) catch return error.BadFooter;
        if (footer.check != d.stream_check) return error.BadFooter;
        if (@as(u64, footer.backward) != used) return error.BadFooter;

        if (!d.opts.multi_stream) {
            d.phase = .done;
            if (!d.opts.ignore_trailing_garbage) {
                _ = d.in.peekByte() catch |e| switch (e) {
                    error.EndOfStream => return,
                    error.ReadFailed => return error.ReadFailed,
                };
                return error.TrailingData;
            }
            return;
        }
        // Stream padding: zero bytes, a multiple of four, then end or a stream.
        var padding: u64 = 0;
        while (true) {
            const b = d.in.peekByte() catch |e| switch (e) {
                error.EndOfStream => {
                    if (padding % 4 != 0) return error.BadFooter;
                    d.phase = .done;
                    return;
                },
                error.ReadFailed => return error.ReadFailed,
            };
            if (b != 0) break;
            d.in.toss(1);
            padding += 1;
        }
        if (padding % 4 != 0) return error.BadFooter;
        d.phase = .start;
    }

    /// A variable-length integer, counted into `used` and `crc`.
    fn vli(d: *Decoder, crc: *std.hash.Crc32, used: *u64) Error!u64 {
        var v: u64 = 0;
        var i: u6 = 0;
        while (true) : (i += 1) {
            if (i == 9) return error.BadIndex;
            const b = try d.readByte();
            crc.update(&.{b});
            used.* += 1;
            v |= @as(u64, b & 0x7F) << (7 * i);
            if (b & 0x80 == 0) {
                if (b == 0 and i != 0) return error.BadIndex;
                return v;
            }
        }
    }
};

/// Decompress a whole buffer. Caller owns the result.
pub fn decompress(gpa: std.mem.Allocator, input: []const u8, format: Format, opts: Options) Error![]u8 {
    var in: Reader = .fixed(input);
    var out: Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = decompressStream(gpa, &in, &out.writer, format, opts) catch |e| switch (e) {
        error.WriteFailed => return error.OutOfMemory,
        else => |x| return x,
    };
    return out.toOwnedSlice() catch error.OutOfMemory;
}

/// Decompress from `in` to `out`; returns the output length. `out` is flushed.
pub fn decompressStream(gpa: std.mem.Allocator, in: *Reader, out: *Writer, format: Format, opts: Options) (Error || error{WriteFailed})!u64 {
    var d = try Decoder.init(gpa, in, format, opts);
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

/// A pull `std.Io.Reader` over the decompressed bytes. A failure is
/// `error.ReadFailed` from the reader with the cause in `err`; at the end the
/// reader reports `EndOfStream`.
pub const DecompressReader = struct {
    /// The interface. Its buffer is the one passed to `init` (it may be empty).
    reader: Reader,
    err: ?Error = null,
    dec: Decoder,

    /// `in` must have a non-empty buffer. Allocates the model; the dictionary
    /// is allocated when the header has been read.
    pub fn init(gpa: std.mem.Allocator, in: *Reader, buffer: []u8, format: Format, opts: Options) error{OutOfMemory}!DecompressReader {
        return .{
            .reader = .{ .vtable = &.{ .stream = stream, .readVec = refillReadVec }, .buffer = buffer, .seek = 0, .end = 0 },
            .dec = try .init(gpa, in, format, opts),
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

/// `readVec` for a reader with only `stream` behind it. Zig 0.17's
/// `defaultReadVec` streams straight into the caller's slice whenever that
/// slice is at least the buffer's free tail, and nothing moves the unread
/// octets back to the front: once the buffer had been filled to its end,
/// every small `readSlice*` became its own `stream` call. Rebasing first
/// leaves the whole buffer free, so a small read refills it.
fn refillReadVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
    const live = r.end - r.seek;
    @memmove(r.buffer[0..live], r.buffer[r.seek..r.end]);
    r.seek = 0;
    r.end = live;
    return std.Io.Reader.defaultReadVec(r, data);
}
