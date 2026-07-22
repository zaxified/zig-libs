//! RFC 7932 Appendix A — the normative Brotli static dictionary.
//!
//! `data` is the 122_784-byte word list, embedded verbatim from the RFC 7932
//! Appendix A constant (identical to google/brotli `c/common/dictionary.bin`,
//! MIT-licensed). It is a normative part of the format: a compliant decoder
//! MUST reference exactly these bytes. `size_bits_by_length` is the RFC 7932
//! Appendix A bucket table; `offsets_by_length` is derived from it at comptime.

const std = @import("std");

/// The static dictionary word data (RFC 7932 Appendix A). 122_784 bytes.
pub const data: []const u8 = @embedFile("dictionary.bin");

pub const min_word_length = 4;
pub const max_word_length = 24;

/// Number of bits used to index a word within the bucket for each word length.
/// Index 0..31; a value of 0 means "no words of this length". RFC 7932 App. A.
pub const size_bits_by_length = [32]u8{
    0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8,
    7, 7, 8, 7, 7,  6,  6,  5,  5,  0,  0,  0,  0,  0, 0, 0,
};

/// Byte offset of each length-bucket in `data`, derived from `size_bits_by_length`.
/// offset[i+1] = offset[i] + (bits[i] != 0 ? i << bits[i] : 0).
pub const offsets_by_length: [32]u32 = blk: {
    var off: [32]u32 = undefined;
    var acc: u32 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        off[i] = acc;
        const bits = size_bits_by_length[i];
        if (bits != 0) acc += @as(u32, @intCast(i)) << @intCast(bits);
    }
    break :blk off;
};

comptime {
    // The derived table must exactly cover the embedded data.
    if (offsets_by_length[25] != data.len) {
        @compileError("brotli dictionary size mismatch with size_bits_by_length");
    }
}
