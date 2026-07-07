// SPDX-License-Identifier: MIT

//! hpack — HPACK header compression for HTTP/2 (RFC 7541), the codec core
//! the future HTTP/2 framing layer sits on. Pure wire codec: no sockets, no
//! I/O — operates on byte slices, allocator-based, and never panics on
//! malformed input (clean errors only).
//!
//! Contents: `Encoder` and `Decoder` (each owning its own dynamic table,
//! §2.3.2/§4), all four header-field representations (§6.1 indexed, §6.2.1
//! incremental literal, §6.2.2 without indexing, §6.2.3 never-indexed),
//! dynamic-table size updates (§6.3), N-bit prefix integers (§5.1) and
//! string literals with the full canonical Huffman code (§5.2 + Appendix B),
//! including the EOS/padding validity rules. The decoder enforces a
//! caller-set maximum header-list size so a hostile peer cannot expand a
//! small block into unbounded memory (decompression-bomb guard).
//!
//! Provenance: clean-room implementation from RFC 7541 only. The static
//! table is the RFC 7541 Appendix A data and the Huffman code table is the
//! RFC 7541 Appendix B data (transcribed from the spec); no third-party
//! HPACK source was consulted or copied. Verified against the RFC 7541
//! Appendix C worked examples (C.1–C.6) as known-answer tests below.

const std = @import("std");
const Allocator = std.mem.Allocator;

// ── public vocabulary ───────────────────────────────────────────────────────

/// One header field. Decoded fields' `name`/`value` are owned by the
/// `HeaderList` they came in; fields passed to `Encoder.encodeBlock` are
/// borrowed for the duration of the call.
pub const Field = struct {
    name: []const u8,
    value: []const u8,
    /// Encoder: emit as never-indexed (§6.2.3) and keep it out of the
    /// dynamic table (for e.g. passwords / cookies with secrets).
    /// Decoder: set when the peer sent the field never-indexed, so an
    /// intermediary re-encoding the list can preserve the protection.
    sensitive: bool = false,
};

/// Everything `Decoder.decodeBlock` can fail with.
pub const DecodeError = error{
    /// Structurally malformed block: truncated input, index 0 / index out
    /// of range, or a size update after the first header field.
    InvalidHpack,
    /// A §5.1 integer exceeds this implementation's 2^32-1 cap (also used
    /// for overlong zero-padded continuations).
    IntegerOverflow,
    /// Invalid Huffman data: explicit EOS symbol, or final padding that is
    /// longer than 7 bits or not all ones (§5.2).
    HuffmanError,
    /// A §6.3 dynamic table size update exceeds the decoder's configured
    /// maximum (SETTINGS_HEADER_TABLE_SIZE).
    TableSizeExceeded,
    /// The decoded header list exceeds `Decoder.Options.max_header_list_size`.
    HeaderListTooLarge,
} || Allocator.Error;

/// Default dynamic-table size, per RFC 7540 SETTINGS_HEADER_TABLE_SIZE.
pub const default_max_table_size: usize = 4096;

/// Default decoder bound on one decoded header list (name + value + 32 per
/// field, the RFC 7540 SETTINGS_MAX_HEADER_LIST_SIZE accounting).
pub const default_max_header_list_size: usize = 64 * 1024;

/// A decoded header block. Owns every `name`/`value` slice.
pub const HeaderList = struct {
    fields: []Field,

    pub fn deinit(hl: *HeaderList, gpa: Allocator) void {
        for (hl.fields) |f| {
            gpa.free(f.name);
            gpa.free(f.value);
        }
        gpa.free(hl.fields);
        hl.* = undefined;
    }
};

// ── §5.1 integer representation ─────────────────────────────────────────────

const max_int: u64 = std.math.maxInt(u32);

/// Append `value` with an N-bit prefix (§5.1). `flags` carries the
/// representation's pattern bits above the prefix.
fn appendInt(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    flags: u8,
    prefix_bits: u4,
    value: u64,
) Allocator.Error!void {
    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;
    if (value < max_prefix) {
        try out.append(gpa, flags | @as(u8, @intCast(value)));
        return;
    }
    try out.append(gpa, flags | @as(u8, @intCast(max_prefix)));
    var v = value - max_prefix;
    while (v >= 0x80) {
        try out.append(gpa, @as(u8, @intCast(v & 0x7f)) | 0x80);
        v >>= 7;
    }
    try out.append(gpa, @intCast(v));
}

/// Bounded input cursor for decoding.
const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(c: *const Cursor) bool {
        return c.pos >= c.buf.len;
    }

    fn take(c: *Cursor) DecodeError!u8 {
        if (c.pos >= c.buf.len) return error.InvalidHpack;
        const b = c.buf[c.pos];
        c.pos += 1;
        return b;
    }

    fn takeSlice(c: *Cursor, n: usize) DecodeError![]const u8 {
        if (c.buf.len - c.pos < n) return error.InvalidHpack;
        const s = c.buf[c.pos..][0..n];
        c.pos += n;
        return s;
    }
};

/// Decode a §5.1 integer whose first byte (already consumed) is `first`.
/// Values are capped at 2^32-1; anything larger — including overlong
/// zero-padded continuations — is `error.IntegerOverflow`.
fn readInt(c: *Cursor, first: u8, prefix_bits: u4) DecodeError!u64 {
    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;
    var value: u64 = first & @as(u8, @intCast(max_prefix));
    if (value < max_prefix) return value;
    var shift: u6 = 0;
    while (true) {
        const b = try c.take();
        if (shift >= 32) return error.IntegerOverflow;
        value += @as(u64, b & 0x7f) << shift;
        if (value > max_int) return error.IntegerOverflow;
        if (b & 0x80 == 0) return value;
        shift += 7;
    }
}

// ── Appendix B canonical Huffman code ───────────────────────────────────────

const HuffCode = struct { code: u32, len: u6 };

/// RFC 7541 Appendix B: code for every octet 0–255 plus EOS (index 256).
const huff_codes = [257]HuffCode{
    .{ .code = 0x1ff8, .len = 13 },     .{ .code = 0x7fffd8, .len = 23 },
    .{ .code = 0xfffffe2, .len = 28 },  .{ .code = 0xfffffe3, .len = 28 },
    .{ .code = 0xfffffe4, .len = 28 },  .{ .code = 0xfffffe5, .len = 28 },
    .{ .code = 0xfffffe6, .len = 28 },  .{ .code = 0xfffffe7, .len = 28 },
    .{ .code = 0xfffffe8, .len = 28 },  .{ .code = 0xffffea, .len = 24 },
    .{ .code = 0x3ffffffc, .len = 30 }, .{ .code = 0xfffffe9, .len = 28 },
    .{ .code = 0xfffffea, .len = 28 },  .{ .code = 0x3ffffffd, .len = 30 },
    .{ .code = 0xfffffeb, .len = 28 },  .{ .code = 0xfffffec, .len = 28 },
    .{ .code = 0xfffffed, .len = 28 },  .{ .code = 0xfffffee, .len = 28 },
    .{ .code = 0xfffffef, .len = 28 },  .{ .code = 0xffffff0, .len = 28 },
    .{ .code = 0xffffff1, .len = 28 },  .{ .code = 0xffffff2, .len = 28 },
    .{ .code = 0x3ffffffe, .len = 30 }, .{ .code = 0xffffff3, .len = 28 },
    .{ .code = 0xffffff4, .len = 28 },  .{ .code = 0xffffff5, .len = 28 },
    .{ .code = 0xffffff6, .len = 28 },  .{ .code = 0xffffff7, .len = 28 },
    .{ .code = 0xffffff8, .len = 28 },  .{ .code = 0xffffff9, .len = 28 },
    .{ .code = 0xffffffa, .len = 28 },  .{ .code = 0xffffffb, .len = 28 },
    .{ .code = 0x14, .len = 6 },        .{ .code = 0x3f8, .len = 10 },
    .{ .code = 0x3f9, .len = 10 },      .{ .code = 0xffa, .len = 12 },
    .{ .code = 0x1ff9, .len = 13 },     .{ .code = 0x15, .len = 6 },
    .{ .code = 0xf8, .len = 8 },        .{ .code = 0x7fa, .len = 11 },
    .{ .code = 0x3fa, .len = 10 },      .{ .code = 0x3fb, .len = 10 },
    .{ .code = 0xf9, .len = 8 },        .{ .code = 0x7fb, .len = 11 },
    .{ .code = 0xfa, .len = 8 },        .{ .code = 0x16, .len = 6 },
    .{ .code = 0x17, .len = 6 },        .{ .code = 0x18, .len = 6 },
    .{ .code = 0x0, .len = 5 },         .{ .code = 0x1, .len = 5 },
    .{ .code = 0x2, .len = 5 },         .{ .code = 0x19, .len = 6 },
    .{ .code = 0x1a, .len = 6 },        .{ .code = 0x1b, .len = 6 },
    .{ .code = 0x1c, .len = 6 },        .{ .code = 0x1d, .len = 6 },
    .{ .code = 0x1e, .len = 6 },        .{ .code = 0x1f, .len = 6 },
    .{ .code = 0x5c, .len = 7 },        .{ .code = 0xfb, .len = 8 },
    .{ .code = 0x7ffc, .len = 15 },     .{ .code = 0x20, .len = 6 },
    .{ .code = 0xffb, .len = 12 },      .{ .code = 0x3fc, .len = 10 },
    .{ .code = 0x1ffa, .len = 13 },     .{ .code = 0x21, .len = 6 },
    .{ .code = 0x5d, .len = 7 },        .{ .code = 0x5e, .len = 7 },
    .{ .code = 0x5f, .len = 7 },        .{ .code = 0x60, .len = 7 },
    .{ .code = 0x61, .len = 7 },        .{ .code = 0x62, .len = 7 },
    .{ .code = 0x63, .len = 7 },        .{ .code = 0x64, .len = 7 },
    .{ .code = 0x65, .len = 7 },        .{ .code = 0x66, .len = 7 },
    .{ .code = 0x67, .len = 7 },        .{ .code = 0x68, .len = 7 },
    .{ .code = 0x69, .len = 7 },        .{ .code = 0x6a, .len = 7 },
    .{ .code = 0x6b, .len = 7 },        .{ .code = 0x6c, .len = 7 },
    .{ .code = 0x6d, .len = 7 },        .{ .code = 0x6e, .len = 7 },
    .{ .code = 0x6f, .len = 7 },        .{ .code = 0x70, .len = 7 },
    .{ .code = 0x71, .len = 7 },        .{ .code = 0x72, .len = 7 },
    .{ .code = 0xfc, .len = 8 },        .{ .code = 0x73, .len = 7 },
    .{ .code = 0xfd, .len = 8 },        .{ .code = 0x1ffb, .len = 13 },
    .{ .code = 0x7fff0, .len = 19 },    .{ .code = 0x1ffc, .len = 13 },
    .{ .code = 0x3ffc, .len = 14 },     .{ .code = 0x22, .len = 6 },
    .{ .code = 0x7ffd, .len = 15 },     .{ .code = 0x3, .len = 5 },
    .{ .code = 0x23, .len = 6 },        .{ .code = 0x4, .len = 5 },
    .{ .code = 0x24, .len = 6 },        .{ .code = 0x5, .len = 5 },
    .{ .code = 0x25, .len = 6 },        .{ .code = 0x26, .len = 6 },
    .{ .code = 0x27, .len = 6 },        .{ .code = 0x6, .len = 5 },
    .{ .code = 0x74, .len = 7 },        .{ .code = 0x75, .len = 7 },
    .{ .code = 0x28, .len = 6 },        .{ .code = 0x29, .len = 6 },
    .{ .code = 0x2a, .len = 6 },        .{ .code = 0x7, .len = 5 },
    .{ .code = 0x2b, .len = 6 },        .{ .code = 0x76, .len = 7 },
    .{ .code = 0x2c, .len = 6 },        .{ .code = 0x8, .len = 5 },
    .{ .code = 0x9, .len = 5 },         .{ .code = 0x2d, .len = 6 },
    .{ .code = 0x77, .len = 7 },        .{ .code = 0x78, .len = 7 },
    .{ .code = 0x79, .len = 7 },        .{ .code = 0x7a, .len = 7 },
    .{ .code = 0x7b, .len = 7 },        .{ .code = 0x7ffe, .len = 15 },
    .{ .code = 0x7fc, .len = 11 },      .{ .code = 0x3ffd, .len = 14 },
    .{ .code = 0x1ffd, .len = 13 },     .{ .code = 0xffffffc, .len = 28 },
    .{ .code = 0xfffe6, .len = 20 },    .{ .code = 0x3fffd2, .len = 22 },
    .{ .code = 0xfffe7, .len = 20 },    .{ .code = 0xfffe8, .len = 20 },
    .{ .code = 0x3fffd3, .len = 22 },   .{ .code = 0x3fffd4, .len = 22 },
    .{ .code = 0x3fffd5, .len = 22 },   .{ .code = 0x7fffd9, .len = 23 },
    .{ .code = 0x3fffd6, .len = 22 },   .{ .code = 0x7fffda, .len = 23 },
    .{ .code = 0x7fffdb, .len = 23 },   .{ .code = 0x7fffdc, .len = 23 },
    .{ .code = 0x7fffdd, .len = 23 },   .{ .code = 0x7fffde, .len = 23 },
    .{ .code = 0xffffeb, .len = 24 },   .{ .code = 0x7fffdf, .len = 23 },
    .{ .code = 0xffffec, .len = 24 },   .{ .code = 0xffffed, .len = 24 },
    .{ .code = 0x3fffd7, .len = 22 },   .{ .code = 0x7fffe0, .len = 23 },
    .{ .code = 0xffffee, .len = 24 },   .{ .code = 0x7fffe1, .len = 23 },
    .{ .code = 0x7fffe2, .len = 23 },   .{ .code = 0x7fffe3, .len = 23 },
    .{ .code = 0x7fffe4, .len = 23 },   .{ .code = 0x1fffdc, .len = 21 },
    .{ .code = 0x3fffd8, .len = 22 },   .{ .code = 0x7fffe5, .len = 23 },
    .{ .code = 0x3fffd9, .len = 22 },   .{ .code = 0x7fffe6, .len = 23 },
    .{ .code = 0x7fffe7, .len = 23 },   .{ .code = 0xffffef, .len = 24 },
    .{ .code = 0x3fffda, .len = 22 },   .{ .code = 0x1fffdd, .len = 21 },
    .{ .code = 0xfffe9, .len = 20 },    .{ .code = 0x3fffdb, .len = 22 },
    .{ .code = 0x3fffdc, .len = 22 },   .{ .code = 0x7fffe8, .len = 23 },
    .{ .code = 0x7fffe9, .len = 23 },   .{ .code = 0x1fffde, .len = 21 },
    .{ .code = 0x7fffea, .len = 23 },   .{ .code = 0x3fffdd, .len = 22 },
    .{ .code = 0x3fffde, .len = 22 },   .{ .code = 0xfffff0, .len = 24 },
    .{ .code = 0x1fffdf, .len = 21 },   .{ .code = 0x3fffdf, .len = 22 },
    .{ .code = 0x7fffeb, .len = 23 },   .{ .code = 0x7fffec, .len = 23 },
    .{ .code = 0x1fffe0, .len = 21 },   .{ .code = 0x1fffe1, .len = 21 },
    .{ .code = 0x3fffe0, .len = 22 },   .{ .code = 0x1fffe2, .len = 21 },
    .{ .code = 0x7fffed, .len = 23 },   .{ .code = 0x3fffe1, .len = 22 },
    .{ .code = 0x7fffee, .len = 23 },   .{ .code = 0x7fffef, .len = 23 },
    .{ .code = 0xfffea, .len = 20 },    .{ .code = 0x3fffe2, .len = 22 },
    .{ .code = 0x3fffe3, .len = 22 },   .{ .code = 0x3fffe4, .len = 22 },
    .{ .code = 0x7ffff0, .len = 23 },   .{ .code = 0x3fffe5, .len = 22 },
    .{ .code = 0x3fffe6, .len = 22 },   .{ .code = 0x7ffff1, .len = 23 },
    .{ .code = 0x3ffffe0, .len = 26 },  .{ .code = 0x3ffffe1, .len = 26 },
    .{ .code = 0xfffeb, .len = 20 },    .{ .code = 0x7fff1, .len = 19 },
    .{ .code = 0x3fffe7, .len = 22 },   .{ .code = 0x7ffff2, .len = 23 },
    .{ .code = 0x3fffe8, .len = 22 },   .{ .code = 0x1ffffec, .len = 25 },
    .{ .code = 0x3ffffe2, .len = 26 },  .{ .code = 0x3ffffe3, .len = 26 },
    .{ .code = 0x3ffffe4, .len = 26 },  .{ .code = 0x7ffffde, .len = 27 },
    .{ .code = 0x7ffffdf, .len = 27 },  .{ .code = 0x3ffffe5, .len = 26 },
    .{ .code = 0xfffff1, .len = 24 },   .{ .code = 0x1ffffed, .len = 25 },
    .{ .code = 0x7fff2, .len = 19 },    .{ .code = 0x1fffe3, .len = 21 },
    .{ .code = 0x3ffffe6, .len = 26 },  .{ .code = 0x7ffffe0, .len = 27 },
    .{ .code = 0x7ffffe1, .len = 27 },  .{ .code = 0x3ffffe7, .len = 26 },
    .{ .code = 0x7ffffe2, .len = 27 },  .{ .code = 0xfffff2, .len = 24 },
    .{ .code = 0x1fffe4, .len = 21 },   .{ .code = 0x1fffe5, .len = 21 },
    .{ .code = 0x3ffffe8, .len = 26 },  .{ .code = 0x3ffffe9, .len = 26 },
    .{ .code = 0xffffffd, .len = 28 },  .{ .code = 0x7ffffe3, .len = 27 },
    .{ .code = 0x7ffffe4, .len = 27 },  .{ .code = 0x7ffffe5, .len = 27 },
    .{ .code = 0xfffec, .len = 20 },    .{ .code = 0xfffff3, .len = 24 },
    .{ .code = 0xfffed, .len = 20 },    .{ .code = 0x1fffe6, .len = 21 },
    .{ .code = 0x3fffe9, .len = 22 },   .{ .code = 0x1fffe7, .len = 21 },
    .{ .code = 0x1fffe8, .len = 21 },   .{ .code = 0x7ffff3, .len = 23 },
    .{ .code = 0x3fffea, .len = 22 },   .{ .code = 0x3fffeb, .len = 22 },
    .{ .code = 0x1ffffee, .len = 25 },  .{ .code = 0x1ffffef, .len = 25 },
    .{ .code = 0xfffff4, .len = 24 },   .{ .code = 0xfffff5, .len = 24 },
    .{ .code = 0x3ffffea, .len = 26 },  .{ .code = 0x7ffff4, .len = 23 },
    .{ .code = 0x3ffffeb, .len = 26 },  .{ .code = 0x7ffffe6, .len = 27 },
    .{ .code = 0x3ffffec, .len = 26 },  .{ .code = 0x3ffffed, .len = 26 },
    .{ .code = 0x7ffffe7, .len = 27 },  .{ .code = 0x7ffffe8, .len = 27 },
    .{ .code = 0x7ffffe9, .len = 27 },  .{ .code = 0x7ffffea, .len = 27 },
    .{ .code = 0x7ffffeb, .len = 27 },  .{ .code = 0xffffffe, .len = 28 },
    .{ .code = 0x7ffffec, .len = 27 },  .{ .code = 0x7ffffed, .len = 27 },
    .{ .code = 0x7ffffee, .len = 27 },  .{ .code = 0x7ffffef, .len = 27 },
    .{ .code = 0x7fffff0, .len = 27 },  .{ .code = 0x3ffffee, .len = 26 },
    .{ .code = 0x3fffffff, .len = 30 },
};

const eos_symbol: u16 = 256;

/// Binary decode tree built at comptime from `huff_codes`. Node 0 is the
/// root; `next[bit] == 0` means "no child" (never hit for a complete code);
/// `sym >= 0` marks a leaf.
const HuffNode = struct { next: [2]u16, sym: i16 };

const huff_tree: [513]HuffNode = buildHuffTree();

fn buildHuffTree() [513]HuffNode {
    @setEvalBranchQuota(200_000);
    var nodes = [_]HuffNode{.{ .next = .{ 0, 0 }, .sym = -1 }} ** 513;
    var n_nodes: u16 = 1;
    for (huff_codes, 0..) |hc, sym| {
        var node: u16 = 0;
        var pos: u6 = hc.len;
        while (pos > 0) {
            pos -= 1;
            const bit: u1 = @intCast((hc.code >> pos) & 1);
            var child = nodes[node].next[bit];
            if (child == 0) {
                child = n_nodes;
                nodes[node].next[bit] = child;
                n_nodes += 1;
            } else if (nodes[child].sym >= 0) {
                @compileError("huffman table conflict: code is not prefix-free");
            }
            if (pos == 0) {
                if (nodes[child].next[0] != 0 or nodes[child].next[1] != 0)
                    @compileError("huffman table conflict: code is not prefix-free");
                nodes[child].sym = @intCast(sym);
            }
            node = child;
        }
    }
    if (n_nodes != 513) @compileError("huffman table incomplete");
    return nodes;
}

/// Encoded length in octets of `s` under the Appendix B code.
fn huffmanEncodedLen(s: []const u8) usize {
    var bits: usize = 0;
    for (s) |b| bits += huff_codes[b].len;
    return (bits + 7) / 8;
}

/// Huffman-encode `s`, padding the final partial octet with EOS-prefix ones.
fn huffmanEncode(gpa: Allocator, out: *std.ArrayList(u8), s: []const u8) Allocator.Error!void {
    var acc: u64 = 0;
    var nbits: u6 = 0;
    for (s) |b| {
        const hc = huff_codes[b];
        acc = (acc << hc.len) | hc.code;
        nbits += hc.len;
        while (nbits >= 8) {
            nbits -= 8;
            try out.append(gpa, @truncate(acc >> nbits));
        }
    }
    if (nbits > 0) {
        const byte: u8 = @truncate((acc << @intCast(8 - @as(u4, @intCast(nbits)))) |
            (@as(u64, 0xff) >> nbits));
        try out.append(gpa, byte);
    }
}

/// Huffman-decode `input` into a fresh allocation, enforcing the §5.2
/// EOS/padding rules and capping the output at `limit` octets
/// (`error.HeaderListTooLarge` beyond — the decompression-bomb guard).
fn huffmanDecodeAlloc(gpa: Allocator, input: []const u8, limit: usize) DecodeError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var node: u16 = 0;
    var depth: u8 = 0; // bits consumed since the last symbol boundary
    var all_ones = true;
    for (input) |byte| {
        var bit_i: u4 = 8;
        while (bit_i > 0) {
            bit_i -= 1;
            const bit: u1 = @intCast((byte >> @intCast(bit_i)) & 1);
            const child = huff_tree[node].next[bit];
            if (child == 0) return error.HuffmanError; // unreachable for a complete code
            if (huff_tree[child].sym >= 0) {
                const sym: u16 = @intCast(huff_tree[child].sym);
                // §5.2: an explicitly encoded EOS is a decoding error.
                if (sym == eos_symbol) return error.HuffmanError;
                if (out.items.len >= limit) return error.HeaderListTooLarge;
                try out.append(gpa, @intCast(sym));
                node = 0;
                depth = 0;
                all_ones = true;
            } else {
                node = child;
                depth += 1;
                if (bit == 0) all_ones = false;
            }
        }
    }
    // §5.2: padding must be a prefix of EOS (all ones), at most 7 bits.
    if (node != 0 and (depth > 7 or !all_ones)) return error.HuffmanError;
    return out.toOwnedSlice(gpa);
}

// ── Appendix A static table ─────────────────────────────────────────────────

const StaticEntry = struct { name: []const u8, value: []const u8 };

/// RFC 7541 Appendix A: the 61 static entries. The array is 0-based;
/// RFC index `i` lives at `static_table[i - 1]`.
const static_table = [61]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

// ── §2.3.2 / §4 dynamic table ───────────────────────────────────────────────

/// §4.1: per-entry overhead added to `name.len + value.len`.
const entry_overhead: usize = 32;

const DynamicTable = struct {
    /// `entries.items[len - 1]` is the newest (dynamic index 1).
    entries: std.ArrayList(TableEntry) = .empty,
    /// Sum of entry sizes (§4.1).
    size: usize = 0,
    /// Current maximum (§4.2); insertions evict down to this.
    max_size: usize,

    const TableEntry = struct { name: []u8, value: []u8 };

    fn entrySize(name: []const u8, value: []const u8) usize {
        return name.len + value.len + entry_overhead;
    }

    fn deinit(t: *DynamicTable, gpa: Allocator) void {
        for (t.entries.items) |e| {
            gpa.free(e.name);
            gpa.free(e.value);
        }
        t.entries.deinit(gpa);
        t.* = undefined;
    }

    fn count(t: *const DynamicTable) usize {
        return t.entries.items.len;
    }

    /// Dynamic index `i` (1 = newest), or null when out of range.
    fn get(t: *const DynamicTable, i: usize) ?TableEntry {
        if (i == 0 or i > t.entries.items.len) return null;
        return t.entries.items[t.entries.items.len - i];
    }

    fn evictOldest(t: *DynamicTable, gpa: Allocator) void {
        const e = t.entries.orderedRemove(0);
        t.size -= entrySize(e.name, e.value);
        gpa.free(e.name);
        gpa.free(e.value);
    }

    /// §4.3: lower the maximum and evict until the table fits.
    fn setMaxSize(t: *DynamicTable, gpa: Allocator, new_max: usize) void {
        t.max_size = new_max;
        while (t.size > t.max_size) t.evictOldest(gpa);
    }

    /// §4.4: insert (duping name/value), evicting from the oldest end. An
    /// entry larger than the whole table empties it and is not inserted —
    /// that is not an error.
    fn add(t: *DynamicTable, gpa: Allocator, name: []const u8, value: []const u8) Allocator.Error!void {
        const esize = entrySize(name, value);
        if (esize > t.max_size) {
            while (t.entries.items.len > 0) t.evictOldest(gpa);
            return;
        }
        while (t.size + esize > t.max_size) t.evictOldest(gpa);
        const n = try gpa.dupe(u8, name);
        errdefer gpa.free(n);
        const v = try gpa.dupe(u8, value);
        errdefer gpa.free(v);
        try t.entries.append(gpa, .{ .name = n, .value = v });
        t.size += esize;
    }

    /// Combined-address-space lookup (§2.3.3): 1..61 static, 62.. dynamic.
    fn lookup(t: *const DynamicTable, index: u64) ?StaticEntry {
        if (index == 0) return null;
        if (index <= static_table.len) return static_table[@intCast(index - 1)];
        const e = t.get(@intCast(index - static_table.len)) orelse return null;
        return .{ .name = e.name, .value = e.value };
    }
};

// ── Decoder ─────────────────────────────────────────────────────────────────

/// HPACK decoder: owns the receiving side's dynamic table. One decoder per
/// HTTP/2 connection; feed it every header block in connection order.
pub const Decoder = struct {
    gpa: Allocator,
    table: DynamicTable,
    /// Ceiling for §6.3 size updates — our SETTINGS_HEADER_TABLE_SIZE.
    settings_max_table_size: usize,
    /// Decompression-bomb guard: cap on one decoded list's total size
    /// (name.len + value.len + 32 per field).
    max_header_list_size: usize,

    pub const Options = struct {
        /// The SETTINGS_HEADER_TABLE_SIZE we advertised to the peer: both
        /// the initial dynamic-table maximum and the ceiling any §6.3 size
        /// update may set.
        max_table_size: usize = default_max_table_size,
        /// Maximum decoded header-list size accepted from the peer.
        max_header_list_size: usize = default_max_header_list_size,
    };

    pub fn init(gpa: Allocator, options: Options) Decoder {
        return .{
            .gpa = gpa,
            .table = .{ .max_size = options.max_table_size },
            .settings_max_table_size = options.max_table_size,
            .max_header_list_size = options.max_header_list_size,
        };
    }

    pub fn deinit(d: *Decoder) void {
        d.table.deinit(d.gpa);
        d.* = undefined;
    }

    /// Lower/raise our advertised SETTINGS_HEADER_TABLE_SIZE. Lowering also
    /// shrinks the live table immediately so memory is bounded even before
    /// the peer acknowledges with a §6.3 update.
    pub fn setMaxTableSize(d: *Decoder, new_max: usize) void {
        d.settings_max_table_size = new_max;
        if (new_max < d.table.max_size) d.table.setMaxSize(d.gpa, new_max);
    }

    /// Decode one complete header block. The returned list owns all its
    /// strings — free with `HeaderList.deinit`. On any error the dynamic
    /// table may have been partially updated; per RFC 7541 §2.2 / RFC 7540
    /// §4.3 a decoding error is a connection error, so the decoder must not
    /// be reused afterwards.
    pub fn decodeBlock(d: *Decoder, block: []const u8) DecodeError!HeaderList {
        var c: Cursor = .{ .buf = block };
        var fields: std.ArrayList(Field) = .empty;
        errdefer {
            for (fields.items) |f| {
                d.gpa.free(f.name);
                d.gpa.free(f.value);
            }
            fields.deinit(d.gpa);
        }

        var list_size: usize = 0;
        var seen_field = false;
        while (!c.done()) {
            const first = try c.take();
            if (first & 0x80 != 0) {
                // §6.1 indexed header field.
                const index = try readInt(&c, first, 7);
                const e = d.table.lookup(index) orelse return error.InvalidHpack;
                try d.appendField(&fields, &list_size, e.name, e.value, false);
                seen_field = true;
            } else if (first & 0x40 != 0) {
                // §6.2.1 literal with incremental indexing.
                const name, const value = try d.readNameValue(&c, first, 6, &list_size);
                defer d.gpa.free(name);
                defer d.gpa.free(value);
                try d.table.add(d.gpa, name, value);
                try d.appendField(&fields, &list_size, name, value, false);
                seen_field = true;
            } else if (first & 0x20 != 0) {
                // §6.3 dynamic table size update — only before any field.
                if (seen_field) return error.InvalidHpack;
                const new_max = try readInt(&c, first, 5);
                if (new_max > d.settings_max_table_size) return error.TableSizeExceeded;
                d.table.setMaxSize(d.gpa, @intCast(new_max));
            } else {
                // §6.2.2 without indexing (0000) / §6.2.3 never indexed (0001).
                const sensitive = first & 0x10 != 0;
                const name, const value = try d.readNameValue(&c, first, 4, &list_size);
                defer d.gpa.free(name);
                defer d.gpa.free(value);
                try d.appendField(&fields, &list_size, name, value, sensitive);
                seen_field = true;
            }
        }

        return .{ .fields = try fields.toOwnedSlice(d.gpa) };
    }

    // Introspection (used by tests; handy for debugging/GOAWAY diagnostics).

    /// Current dynamic-table size in octets (§4.1 accounting).
    pub fn dynamicTableSize(d: *const Decoder) usize {
        return d.table.size;
    }

    /// Number of dynamic-table entries.
    pub fn dynamicTableCount(d: *const Decoder) usize {
        return d.table.count();
    }

    /// Dynamic-table entry `i` (1 = newest). Slices are valid only until
    /// the next `decodeBlock`/`setMaxTableSize` call.
    pub fn dynamicTableEntry(d: *const Decoder, i: usize) ?Field {
        const e = d.table.get(i) orelse return null;
        return .{ .name = e.name, .value = e.value };
    }

    /// Read the (name, value) of a literal representation whose name is
    /// either an index in the `prefix_bits` prefix or a literal string.
    /// Both returned slices are gpa-owned.
    fn readNameValue(
        d: *Decoder,
        c: *Cursor,
        first: u8,
        prefix_bits: u4,
        list_size: *const usize,
    ) DecodeError!struct { []u8, []u8 } {
        const name_index = try readInt(c, first, prefix_bits);
        const name = if (name_index != 0) blk: {
            const e = d.table.lookup(name_index) orelse return error.InvalidHpack;
            break :blk try d.gpa.dupe(u8, e.name);
        } else try d.readString(c, list_size.*);
        errdefer d.gpa.free(name);
        const value = try d.readString(c, list_size.*);
        return .{ name, value };
    }

    /// Read one §5.2 string literal into a gpa-owned slice, bounding the
    /// decoded length by the remaining header-list budget.
    fn readString(d: *Decoder, c: *Cursor, used: usize) DecodeError![]u8 {
        const budget = d.max_header_list_size -| used;
        const first = try c.take();
        const huffman = first & 0x80 != 0;
        const len = try readInt(c, first, 7);
        if (len > c.buf.len - c.pos) return error.InvalidHpack;
        const raw = try c.takeSlice(@intCast(len));
        if (!huffman) {
            if (raw.len > budget) return error.HeaderListTooLarge;
            return d.gpa.dupe(u8, raw);
        }
        return huffmanDecodeAlloc(d.gpa, raw, budget);
    }

    /// Charge the field against the list budget, dupe and append it.
    fn appendField(
        d: *Decoder,
        fields: *std.ArrayList(Field),
        list_size: *usize,
        name: []const u8,
        value: []const u8,
        sensitive: bool,
    ) DecodeError!void {
        const fsize = DynamicTable.entrySize(name, value);
        if (fsize > d.max_header_list_size - list_size.*) return error.HeaderListTooLarge;
        list_size.* += fsize;
        const n = try d.gpa.dupe(u8, name);
        errdefer d.gpa.free(n);
        const v = try d.gpa.dupe(u8, value);
        errdefer d.gpa.free(v);
        try fields.append(d.gpa, .{ .name = n, .value = v, .sensitive = sensitive });
    }
};

// ── Encoder ─────────────────────────────────────────────────────────────────

/// HPACK encoder: owns the sending side's dynamic table. One encoder per
/// HTTP/2 connection; encode every header block through it in order.
///
/// Strategy: exact (name, value) match in the static or dynamic table →
/// §6.1 indexed; otherwise a §6.2.1 literal with incremental indexing
/// (name-indexed when the name is known), which also inserts the field into
/// the dynamic table. Fields marked `sensitive` are sent §6.2.3
/// never-indexed and stay out of the table.
pub const Encoder = struct {
    gpa: Allocator,
    table: DynamicTable,
    huffman: HuffmanMode,
    /// Pending §6.3 updates to emit at the start of the next block: when
    /// the limit was lowered then raised between blocks, both the minimum
    /// and the final value must be signalled (§4.2).
    pending_min: ?usize = null,
    pending_final: ?usize = null,

    pub const HuffmanMode = enum {
        /// Huffman-encode a string whenever that is no longer than the raw
        /// octets (ties go to Huffman, matching the RFC 7541 Appendix C
        /// examples).
        auto,
        /// Always send raw octets.
        never,
    };

    pub const Options = struct {
        /// Dynamic-table maximum. Must not exceed the peer's
        /// SETTINGS_HEADER_TABLE_SIZE (4096 unless it said otherwise).
        max_table_size: usize = default_max_table_size,
        huffman: HuffmanMode = .auto,
    };

    pub fn init(gpa: Allocator, options: Options) Encoder {
        return .{
            .gpa = gpa,
            .table = .{ .max_size = options.max_table_size },
            .huffman = options.huffman,
        };
    }

    pub fn deinit(e: *Encoder) void {
        e.table.deinit(e.gpa);
        e.* = undefined;
    }

    /// Change the dynamic-table maximum (e.g. the peer lowered its
    /// SETTINGS_HEADER_TABLE_SIZE). Takes effect immediately on the table;
    /// the required §6.3 update(s) are emitted at the start of the next
    /// `encodeBlock`.
    pub fn setMaxTableSize(e: *Encoder, new_max: usize) void {
        e.pending_min = @min(e.pending_min orelse new_max, new_max);
        e.pending_final = new_max;
        e.table.setMaxSize(e.gpa, new_max);
    }

    /// Encode `fields` as one header block, appending to `out`. Note:
    /// `out` is grown with the encoder's allocator, so it must be a list
    /// managed by the same allocator that was passed to `init`.
    pub fn encodeBlock(
        e: *Encoder,
        fields: []const Field,
        out: *std.ArrayList(u8),
    ) Allocator.Error!void {
        if (e.pending_min) |min| {
            try appendInt(e.gpa, out, 0x20, 5, min);
            const final = e.pending_final.?;
            if (final != min) try appendInt(e.gpa, out, 0x20, 5, final);
            e.pending_min = null;
            e.pending_final = null;
        }
        for (fields) |f| try e.encodeField(f, out);
    }

    /// Current dynamic-table size in octets (§4.1 accounting).
    pub fn dynamicTableSize(e: *const Encoder) usize {
        return e.table.size;
    }

    /// Number of dynamic-table entries.
    pub fn dynamicTableCount(e: *const Encoder) usize {
        return e.table.count();
    }

    /// Dynamic-table entry `i` (1 = newest). Slices are valid only until
    /// the next `encodeBlock`/`setMaxTableSize` call.
    pub fn dynamicTableEntry(e: *const Encoder, i: usize) ?Field {
        const entry = e.table.get(i) orelse return null;
        return .{ .name = entry.name, .value = entry.value };
    }

    fn encodeField(e: *Encoder, f: Field, out: *std.ArrayList(u8)) Allocator.Error!void {
        if (f.sensitive) {
            // §6.2.3 literal never indexed.
            try e.encodeLiteral(f, 0x10, 4, out);
            return;
        }
        if (e.findExact(f)) |index| {
            // §6.1 indexed.
            try appendInt(e.gpa, out, 0x80, 7, index);
            return;
        }
        // §6.2.1 literal with incremental indexing.
        try e.encodeLiteral(f, 0x40, 6, out);
        try e.table.add(e.gpa, f.name, f.value);
    }

    /// Emit a literal representation with pattern `flags` / `prefix_bits`,
    /// using a name index when the name exists in either table.
    fn encodeLiteral(
        e: *Encoder,
        f: Field,
        flags: u8,
        prefix_bits: u4,
        out: *std.ArrayList(u8),
    ) Allocator.Error!void {
        if (e.findName(f.name)) |index| {
            try appendInt(e.gpa, out, flags, prefix_bits, index);
        } else {
            try appendInt(e.gpa, out, flags, prefix_bits, 0);
            try e.appendString(out, f.name);
        }
        try e.appendString(out, f.value);
    }

    /// Emit a §5.2 string literal, Huffman-coded per `e.huffman`.
    fn appendString(e: *Encoder, out: *std.ArrayList(u8), s: []const u8) Allocator.Error!void {
        if (e.huffman == .auto) {
            const hlen = huffmanEncodedLen(s);
            if (hlen <= s.len) {
                try appendInt(e.gpa, out, 0x80, 7, hlen);
                try huffmanEncode(e.gpa, out, s);
                return;
            }
        }
        try appendInt(e.gpa, out, 0x00, 7, s.len);
        try out.appendSlice(e.gpa, s);
    }

    /// Combined index of an exact (name, value) match; static entries win.
    fn findExact(e: *const Encoder, f: Field) ?u64 {
        for (static_table, 1..) |s, i| {
            if (std.mem.eql(u8, s.name, f.name) and std.mem.eql(u8, s.value, f.value))
                return i;
        }
        const n = e.table.count();
        var i: usize = 1;
        while (i <= n) : (i += 1) {
            const entry = e.table.get(i).?;
            if (std.mem.eql(u8, entry.name, f.name) and std.mem.eql(u8, entry.value, f.value))
                return static_table.len + i;
        }
        return null;
    }

    /// Combined index of a name-only match; static entries win.
    fn findName(e: *const Encoder, name: []const u8) ?u64 {
        for (static_table, 1..) |s, i| {
            if (std.mem.eql(u8, s.name, name)) return i;
        }
        const n = e.table.count();
        var i: usize = 1;
        while (i <= n) : (i += 1) {
            if (std.mem.eql(u8, e.table.get(i).?.name, name)) return static_table.len + i;
        }
        return null;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Comptime hex-string (spaces/newlines ignored) → bytes.
fn hx(comptime hex: []const u8) []const u8 {
    return comptime blk: {
        @setEvalBranchQuota(100_000);
        var out: []const u8 = &.{};
        var hi: ?u8 = null;
        for (hex) |ch| {
            if (ch == ' ' or ch == '\n') continue;
            const d = std.fmt.charToDigit(ch, 16) catch unreachable;
            if (hi) |h| {
                out = out ++ &[_]u8{h * 16 + d};
                hi = null;
            } else hi = d;
        }
        if (hi != null) unreachable;
        break :blk out;
    };
}

fn expectFields(hl: HeaderList, expected: []const Field) !void {
    try testing.expectEqual(expected.len, hl.fields.len);
    for (expected, hl.fields) |e, a| {
        try testing.expectEqualStrings(e.name, a.name);
        try testing.expectEqualStrings(e.value, a.value);
        try testing.expectEqual(e.sensitive, a.sensitive);
    }
}

/// One RFC Appendix C step: encoder produces the exact RFC bytes, decoder
/// returns the exact fields, and both dynamic tables match the RFC state
/// (`expected_table` newest-first, `expected_size` in octets).
fn expectStep(
    enc: *Encoder,
    dec: *Decoder,
    fields: []const Field,
    expected_bytes: []const u8,
    expected_table: []const Field,
    expected_size: usize,
) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try enc.encodeBlock(fields, &out);
    try testing.expectEqualSlices(u8, expected_bytes, out.items);

    var hl = try dec.decodeBlock(out.items);
    defer hl.deinit(testing.allocator);
    try expectFields(hl, fields);

    try testing.expectEqual(expected_size, enc.dynamicTableSize());
    try testing.expectEqual(expected_size, dec.dynamicTableSize());
    try testing.expectEqual(expected_table.len, enc.dynamicTableCount());
    try testing.expectEqual(expected_table.len, dec.dynamicTableCount());
    for (expected_table, 1..) |t, i| {
        const de = dec.dynamicTableEntry(i).?;
        try testing.expectEqualStrings(t.name, de.name);
        try testing.expectEqualStrings(t.value, de.value);
        const ee = enc.dynamicTableEntry(i).?;
        try testing.expectEqualStrings(t.name, ee.name);
        try testing.expectEqualStrings(t.value, ee.value);
    }
}

fn expectDecodeError(expected: anyerror, block: []const u8) !void {
    var dec: Decoder = .init(testing.allocator, .{});
    defer dec.deinit();
    try testing.expectError(expected, dec.decodeBlock(block));
}

test "integer: RFC 7541 C.1 examples" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    // C.1.1: 10, 5-bit prefix.
    try appendInt(gpa, &out, 0, 5, 10);
    try testing.expectEqualSlices(u8, &.{0x0a}, out.items);
    // C.1.2: 1337, 5-bit prefix.
    out.clearRetainingCapacity();
    try appendInt(gpa, &out, 0, 5, 1337);
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x9a, 0x0a }, out.items);
    // C.1.3: 42, full-octet prefix.
    out.clearRetainingCapacity();
    try appendInt(gpa, &out, 0, 8, 42);
    try testing.expectEqualSlices(u8, &.{0x2a}, out.items);

    var c: Cursor = .{ .buf = &.{0x0a} };
    try testing.expectEqual(@as(u64, 10), try readInt(&c, try c.take(), 5));
    c = .{ .buf = &.{ 0x1f, 0x9a, 0x0a } };
    try testing.expectEqual(@as(u64, 1337), try readInt(&c, try c.take(), 5));
    c = .{ .buf = &.{0x2a} };
    try testing.expectEqual(@as(u64, 42), try readInt(&c, try c.take(), 8));
}

test "integer: round-trips, boundaries and errors" {
    const gpa = testing.allocator;
    const values = [_]u64{ 0, 1, 30, 31, 32, 127, 128, 254, 255, 256, 16383, 16384, max_int };
    for (values) |v| {
        inline for ([_]u4{ 1, 4, 5, 6, 7, 8 }) |prefix| {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(gpa);
            try appendInt(gpa, &out, 0, prefix, v);
            var c: Cursor = .{ .buf = out.items };
            try testing.expectEqual(v, try readInt(&c, try c.take(), prefix));
            try testing.expect(c.done());
        }
    }

    // Truncated continuation.
    var c: Cursor = .{ .buf = &.{0x1f} };
    try testing.expectError(error.InvalidHpack, readInt(&c, try c.take(), 5));
    c = .{ .buf = &.{ 0x1f, 0x80 } };
    try testing.expectError(error.InvalidHpack, readInt(&c, try c.take(), 5));
    // Value above the 2^32-1 cap.
    c = .{ .buf = &.{ 0x1f, 0xff, 0xff, 0xff, 0xff, 0x0f } };
    try testing.expectError(error.IntegerOverflow, readInt(&c, try c.take(), 5));
    // Overlong zero-padded continuation.
    c = .{ .buf = &.{ 0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 } };
    try testing.expectError(error.IntegerOverflow, readInt(&c, try c.take(), 5));
}

test "huffman: Appendix B table is a complete canonical code" {
    var kraft: u64 = 0;
    for (huff_codes) |hc| {
        try testing.expect(hc.len >= 5 and hc.len <= 30);
        try testing.expect(hc.code < @as(u64, 1) << hc.len);
        kraft += @as(u64, 1) << @intCast(30 - hc.len);
    }
    // A complete prefix code satisfies Kraft's equality exactly.
    try testing.expectEqual(@as(u64, 1) << 30, kraft);
}

test "huffman: round-trips every octet and assorted strings" {
    const gpa = testing.allocator;
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);

    const cases = [_][]const u8{ "", "a", "www.example.com", "no-cache", &all };
    for (cases) |s| {
        var enc: std.ArrayList(u8) = .empty;
        defer enc.deinit(gpa);
        try huffmanEncode(gpa, &enc, s);
        try testing.expectEqual(huffmanEncodedLen(s), enc.items.len);
        const dec = try huffmanDecodeAlloc(gpa, enc.items, 1 << 20);
        defer gpa.free(dec);
        try testing.expectEqualStrings(s, dec);
    }
}

test "huffman: EOS and padding rules" {
    const gpa = testing.allocator;
    // 'a' = 00011 + 3 one-bits of padding = 0x1f.
    const a = try huffmanDecodeAlloc(gpa, &.{0x1f}, 16);
    defer gpa.free(a);
    try testing.expectEqualStrings("a", a);
    // Padding of exactly 7 ones after '0' (00000) = 0000 0111 1111 1... no:
    // '0' + 3 ones fits one byte: 0000 0111 = 0x07.
    const zero = try huffmanDecodeAlloc(gpa, &.{0x07}, 16);
    defer gpa.free(zero);
    try testing.expectEqualStrings("0", zero);
    // Padding not all ones.
    try testing.expectError(error.HuffmanError, huffmanDecodeAlloc(gpa, &.{0x06}, 16));
    // Padding of 8 bits (no symbol consumed) is longer than 7.
    try testing.expectError(error.HuffmanError, huffmanDecodeAlloc(gpa, &.{0xff}, 16));
    // Explicitly encoded EOS (30 ones) is a decoding error.
    try testing.expectError(error.HuffmanError, huffmanDecodeAlloc(gpa, &.{ 0xff, 0xff, 0xff, 0xff }, 16));
    // Output cap (decompression-bomb guard).
    var enc: std.ArrayList(u8) = .empty;
    defer enc.deinit(gpa);
    try huffmanEncode(gpa, &enc, "0" ** 100);
    try testing.expectError(error.HeaderListTooLarge, huffmanDecodeAlloc(gpa, enc.items, 99));
}

test "static table: Appendix A spot checks" {
    try testing.expectEqual(@as(usize, 61), static_table.len);
    try testing.expectEqualStrings(":authority", static_table[0].name);
    try testing.expectEqualStrings("GET", static_table[1].value);
    try testing.expectEqualStrings(":status", static_table[7].name);
    try testing.expectEqualStrings("200", static_table[7].value);
    try testing.expectEqualStrings("accept-encoding", static_table[15].name);
    try testing.expectEqualStrings("gzip, deflate", static_table[15].value);
    try testing.expectEqualStrings("www-authenticate", static_table[60].name);
}

test "RFC 7541 C.2.1: literal with incremental indexing" {
    var enc: Encoder = .init(testing.allocator, .{ .huffman = .never });
    defer enc.deinit();
    var dec: Decoder = .init(testing.allocator, .{});
    defer dec.deinit();
    try expectStep(
        &enc,
        &dec,
        &.{.{ .name = "custom-key", .value = "custom-header" }},
        hx("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"),
        &.{.{ .name = "custom-key", .value = "custom-header" }},
        55,
    );
}

test "RFC 7541 C.2.2: literal without indexing (decode)" {
    var dec: Decoder = .init(testing.allocator, .{});
    defer dec.deinit();
    var hl = try dec.decodeBlock(hx("040c 2f73 616d 706c 652f 7061 7468"));
    defer hl.deinit(testing.allocator);
    try expectFields(hl, &.{.{ .name = ":path", .value = "/sample/path" }});
    try testing.expectEqual(@as(usize, 0), dec.dynamicTableCount());
}

test "RFC 7541 C.2.3: literal never indexed" {
    var enc: Encoder = .init(testing.allocator, .{ .huffman = .never });
    defer enc.deinit();
    var dec: Decoder = .init(testing.allocator, .{});
    defer dec.deinit();
    try expectStep(
        &enc,
        &dec,
        &.{.{ .name = "password", .value = "secret", .sensitive = true }},
        hx("1008 7061 7373 776f 7264 0673 6563 7265 74"),
        &.{},
        0,
    );
}

test "RFC 7541 C.2.4: indexed header field" {
    var enc: Encoder = .init(testing.allocator, .{ .huffman = .never });
    defer enc.deinit();
    var dec: Decoder = .init(testing.allocator, .{});
    defer dec.deinit();
    try expectStep(
        &enc,
        &dec,
        &.{.{ .name = ":method", .value = "GET" }},
        hx("82"),
        &.{},
        0,
    );
}

// The three C.3/C.4 request header lists.
const c3_request_1 = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "www.example.com" },
};
const c3_request_2 = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = "cache-control", .value = "no-cache" },
};
const c3_request_3 = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = "custom-key", .value = "custom-value" },
};
const c3_table_1 = [_]Field{
    .{ .name = ":authority", .value = "www.example.com" },
};
const c3_table_2 = [_]Field{
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = ":authority", .value = "www.example.com" },
};
const c3_table_3 = [_]Field{
    .{ .name = "custom-key", .value = "custom-value" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = ":authority", .value = "www.example.com" },
};

test "RFC 7541 C.3: request examples without Huffman" {
    var enc: Encoder = .init(testing.allocator, .{ .huffman = .never });
    defer enc.deinit();
    var dec: Decoder = .init(testing.allocator, .{});
    defer dec.deinit();

    try expectStep(&enc, &dec, &c3_request_1, hx(
        "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
    ), &c3_table_1, 57);
    try expectStep(&enc, &dec, &c3_request_2, hx(
        "8286 84be 5808 6e6f 2d63 6163 6865",
    ), &c3_table_2, 110);
    try expectStep(&enc, &dec, &c3_request_3, hx(
        "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
    ), &c3_table_3, 164);
}

test "RFC 7541 C.4: request examples with Huffman" {
    var enc: Encoder = .init(testing.allocator, .{ .huffman = .auto });
    defer enc.deinit();
    var dec: Decoder = .init(testing.allocator, .{});
    defer dec.deinit();

    try expectStep(&enc, &dec, &c3_request_1, hx(
        "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
    ), &c3_table_1, 57);
    try expectStep(&enc, &dec, &c3_request_2, hx(
        "8286 84be 5886 a8eb 1064 9cbf",
    ), &c3_table_2, 110);
    try expectStep(&enc, &dec, &c3_request_3, hx(
        "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
    ), &c3_table_3, 164);
}

// The three C.5/C.6 response header lists (dynamic table limited to 256).
const c5_response_1 = [_]Field{
    .{ .name = ":status", .value = "302" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
};
const c5_response_2 = [_]Field{
    .{ .name = ":status", .value = "307" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
};
const c5_response_3 = [_]Field{
    .{ .name = ":status", .value = "200" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{
        .name = "set-cookie",
        .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
    },
};
const c5_table_1 = [_]Field{
    .{ .name = "location", .value = "https://www.example.com" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = ":status", .value = "302" },
};
const c5_table_2 = [_]Field{
    .{ .name = ":status", .value = "307" },
    .{ .name = "location", .value = "https://www.example.com" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "cache-control", .value = "private" },
};
const c5_table_3 = [_]Field{
    .{
        .name = "set-cookie",
        .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
    },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
};

test "RFC 7541 C.5: response examples without Huffman (eviction)" {
    var enc: Encoder = .init(testing.allocator, .{ .max_table_size = 256, .huffman = .never });
    defer enc.deinit();
    var dec: Decoder = .init(testing.allocator, .{ .max_table_size = 256 });
    defer dec.deinit();

    try expectStep(&enc, &dec, &c5_response_1, hx(
        \\4803 3330 3258 0770 7269 7661 7465 611d
        \\4d6f 6e2c 2032 3120 4f63 7420 3230 3133
        \\2032 303a 3133 3a32 3120 474d 546e 1768
        \\7474 7073 3a2f 2f77 7777 2e65 7861 6d70
        \\6c65 2e63 6f6d
    ), &c5_table_1, 222);
    try expectStep(&enc, &dec, &c5_response_2, hx(
        "4803 3330 37c1 c0bf",
    ), &c5_table_2, 222);
    try expectStep(&enc, &dec, &c5_response_3, hx(
        \\88c1 611d 4d6f 6e2c 2032 3120 4f63 7420
        \\3230 3133 2032 303a 3133 3a32 3220 474d
        \\54c0 5a04 677a 6970 7738 666f 6f3d 4153
        \\444a 4b48 514b 425a 584f 5157 454f 5049
        \\5541 5851 5745 4f49 553b 206d 6178 2d61
        \\6765 3d33 3630 303b 2076 6572 7369 6f6e
        \\3d31
    ), &c5_table_3, 215);
}

test "RFC 7541 C.6: response examples with Huffman (eviction)" {
    var enc: Encoder = .init(testing.allocator, .{ .max_table_size = 256, .huffman = .auto });
    defer enc.deinit();
    var dec: Decoder = .init(testing.allocator, .{ .max_table_size = 256 });
    defer dec.deinit();

    try expectStep(&enc, &dec, &c5_response_1, hx(
        \\4882 6402 5885 aec3 771a 4b61 96d0 7abe
        \\9410 54d4 44a8 2005 9504 0b81 66e0 82a6
        \\2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8
        \\e9ae 82ae 43d3
    ), &c5_table_1, 222);
    try expectStep(&enc, &dec, &c5_response_2, hx(
        "4883 640e ffc1 c0bf",
    ), &c5_table_2, 222);
    try expectStep(&enc, &dec, &c5_response_3, hx(
        \\88c1 6196 d07a be94 1054 d444 a820 0595
        \\040b 8166 e084 a62d 1bff c05a 839b d9ab
        \\77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b
        \\3960 d5af 2708 7f36 72c1 ab27 0fb5 291f
        \\9587 3160 65c0 03ed 4ee5 b106 3d50 07
    ), &c5_table_3, 215);
}

test "size update: encoder emits, decoder applies (§6.3)" {
    const gpa = testing.allocator;
    var enc: Encoder = .init(gpa, .{ .huffman = .never });
    defer enc.deinit();
    var dec: Decoder = .init(gpa, .{});
    defer dec.deinit();

    // Populate both tables.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try enc.encodeBlock(&.{.{ .name = "custom-key", .value = "custom-header" }}, &out);
    var hl = try dec.decodeBlock(out.items);
    hl.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), dec.dynamicTableCount());

    // Shrink to 0, then raise to 100: both updates must be signalled.
    enc.setMaxTableSize(0);
    enc.setMaxTableSize(100);
    try testing.expectEqual(@as(usize, 0), enc.dynamicTableCount());
    out.clearRetainingCapacity();
    try enc.encodeBlock(&.{}, &out);
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x3f, 0x45 }, out.items);

    hl = try dec.decodeBlock(out.items);
    hl.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), dec.dynamicTableCount());
    try testing.expectEqual(@as(usize, 100), dec.table.max_size);

    // An update above the decoder's SETTINGS value is rejected.
    var small: Decoder = .init(gpa, .{ .max_table_size = 100 });
    defer small.deinit();
    var upd: std.ArrayList(u8) = .empty;
    defer upd.deinit(gpa);
    try appendInt(gpa, &upd, 0x20, 5, 101);
    try testing.expectError(error.TableSizeExceeded, small.decodeBlock(upd.items));

    // A size update after the first field is malformed.
    try expectDecodeError(error.InvalidHpack, &.{ 0x82, 0x20 });
}

test "decoder: malformed inputs return clean errors" {
    // Index 0.
    try expectDecodeError(error.InvalidHpack, &.{0x80});
    // Index beyond static + (empty) dynamic table.
    try expectDecodeError(error.InvalidHpack, &.{0xc5});
    // Name index beyond the tables in a literal.
    try expectDecodeError(error.InvalidHpack, &.{ 0x7f, 0x2f, 0x00 });
    // Truncated integer.
    try expectDecodeError(error.InvalidHpack, &.{0xff});
    try expectDecodeError(error.InvalidHpack, &.{ 0xff, 0x80, 0x80 });
    // Integer overflow.
    try expectDecodeError(error.IntegerOverflow, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f });
    // Truncated string literal.
    try expectDecodeError(error.InvalidHpack, &.{ 0x00, 0x05, 'a', 'b' });
    // String length integer itself truncated.
    try expectDecodeError(error.InvalidHpack, &.{ 0x00, 0x7f });
    // Bad Huffman padding inside a string literal.
    try expectDecodeError(error.HuffmanError, &.{ 0x00, 0x81, 0xff, 0x01, 'x' });
    // Explicit EOS inside a string literal.
    try expectDecodeError(error.HuffmanError, &.{ 0x00, 0x84, 0xff, 0xff, 0xff, 0xff, 0x01, 'x' });
    // Empty block is fine.
    var dec: Decoder = .init(testing.allocator, .{});
    defer dec.deinit();
    var hl = try dec.decodeBlock(&.{});
    defer hl.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), hl.fields.len);
}

test "decoder: header-list size limit bounds memory" {
    const gpa = testing.allocator;
    var enc: Encoder = .init(gpa, .{});
    defer enc.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try enc.encodeBlock(&.{
        .{ .name = "x-a", .value = "ok" },
        .{ .name = "x-large", .value = "0123456789" ** 10 },
    }, &out);

    // Large enough limit: fine.
    var dec_ok: Decoder = .init(gpa, .{ .max_header_list_size = 512 });
    defer dec_ok.deinit();
    var hl = try dec_ok.decodeBlock(out.items);
    hl.deinit(gpa);

    // Tight limit: the second field blows the budget.
    var dec_small: Decoder = .init(gpa, .{ .max_header_list_size = 64 });
    defer dec_small.deinit();
    try testing.expectError(error.HeaderListTooLarge, dec_small.decodeBlock(out.items));

    // The cap applies while Huffman-inflating, before the full string
    // materializes (decompression-bomb guard).
    var dec_tiny: Decoder = .init(gpa, .{ .max_header_list_size = 40 });
    defer dec_tiny.deinit();
    try testing.expectError(error.HeaderListTooLarge, dec_tiny.decodeBlock(out.items));
}

test "dynamic table: oversized entry clears the table (§4.4)" {
    const gpa = testing.allocator;
    var enc: Encoder = .init(gpa, .{ .max_table_size = 64, .huffman = .never });
    defer enc.deinit();
    var dec: Decoder = .init(gpa, .{ .max_table_size = 64 });
    defer dec.deinit();

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try enc.encodeBlock(&.{.{ .name = "x-small", .value = "v" }}, &out);
    var hl = try dec.decodeBlock(out.items);
    hl.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), dec.dynamicTableCount());

    out.clearRetainingCapacity();
    try enc.encodeBlock(&.{.{ .name = "x-big", .value = "0123456789" ** 8 }}, &out);
    hl = try dec.decodeBlock(out.items);
    defer hl.deinit(gpa);
    try expectFields(hl, &.{.{ .name = "x-big", .value = "0123456789" ** 8 }});
    try testing.expectEqual(@as(usize, 0), enc.dynamicTableCount());
    try testing.expectEqual(@as(usize, 0), dec.dynamicTableCount());
    try testing.expectEqual(@as(usize, 0), dec.dynamicTableSize());
}

test "round trip: assorted header lists through both Huffman modes" {
    const gpa = testing.allocator;
    const blocks = [_][]const Field{
        &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":path", .value = "/submit?q=a%20b" },
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "x-custom", .value = "Value With CAPS and spaces" },
            .{ .name = "authorization", .value = "Bearer abc.def.ghi", .sensitive = true },
        },
        &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = "x-custom", .value = "Value With CAPS and spaces" },
            .{ .name = "x-empty", .value = "" },
            .{ .name = "x-binary", .value = "\x00\x01\xfe\xff\x7f\x80" },
        },
        &.{
            .{ .name = "cookie", .value = "session=deadbeef", .sensitive = true },
            .{ .name = "x-custom", .value = "changed" },
        },
    };

    inline for ([_]Encoder.HuffmanMode{ .auto, .never }) |mode| {
        var enc: Encoder = .init(gpa, .{ .huffman = mode });
        defer enc.deinit();
        var dec: Decoder = .init(gpa, .{});
        defer dec.deinit();
        for (blocks) |fields| {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(gpa);
            try enc.encodeBlock(fields, &out);
            var hl = try dec.decodeBlock(out.items);
            defer hl.deinit(gpa);
            try expectFields(hl, fields);
            // Encoder and decoder tables stay in lockstep.
            try testing.expectEqual(enc.dynamicTableSize(), dec.dynamicTableSize());
            try testing.expectEqual(enc.dynamicTableCount(), dec.dynamicTableCount());
        }
        // Sensitive fields never entered the dynamic table.
        var i: usize = 1;
        while (dec.dynamicTableEntry(i)) |e| : (i += 1) {
            try testing.expect(!std.mem.eql(u8, e.name, "authorization"));
            try testing.expect(!std.mem.eql(u8, e.name, "cookie"));
        }
    }
}

test "decoder: setMaxTableSize shrinks the live table" {
    const gpa = testing.allocator;
    var enc: Encoder = .init(gpa, .{ .huffman = .never });
    defer enc.deinit();
    var dec: Decoder = .init(gpa, .{});
    defer dec.deinit();

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try enc.encodeBlock(&.{
        .{ .name = "x-one", .value = "1" },
        .{ .name = "x-two", .value = "2" },
    }, &out);
    var hl = try dec.decodeBlock(out.items);
    hl.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), dec.dynamicTableCount());

    dec.setMaxTableSize(40); // each entry is 38 octets — only the newest fits
    try testing.expectEqual(@as(usize, 1), dec.dynamicTableCount());
    try testing.expectEqualStrings("x-two", dec.dynamicTableEntry(1).?.name);
    dec.setMaxTableSize(0);
    try testing.expectEqual(@as(usize, 0), dec.dynamicTableCount());
}
