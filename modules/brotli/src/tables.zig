//! Normative constant tables for RFC 7932 decoding: the context-model lookup
//! table (Appendix C style, from google/brotli context.c), the block-length
//! prefix ranges, the command (insert-and-copy) lookup table, and the code
//! length code order + the fixed prefix code for reading code length codes.

// ---------------------------------------------------------------------------
// Constants (RFC 7932).
pub const num_literal_symbols = 256;
pub const num_command_symbols = 704;
pub const num_block_len_symbols = 26;
pub const num_distance_short_codes = 16;
pub const code_length_codes = 18; // symbols 0..17
pub const repeat_previous_code_length = 16;
pub const repeat_zero_code_length = 17;
pub const initial_repeated_code_length = 8;
pub const max_code_length = 15;
pub const literal_context_bits = 6;
pub const distance_context_bits = 2;
pub const max_distance_bits = 24;
pub const max_allowed_distance = 0x7FFFFFFC;

/// BROTLI_DISTANCE_ALPHABET_SIZE(npostfix, ndirect, maxnbits).
pub fn distanceAlphabetSize(npostfix: u32, ndirect: u32, maxnbits: u32) u32 {
    return num_distance_short_codes + ndirect + (maxnbits << @intCast(npostfix + 1));
}

// ---------------------------------------------------------------------------
// Code length code order + fixed prefix code (RFC 7932 3.5).
pub const code_length_code_order = [code_length_codes]u8{
    1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15,
};
pub const code_length_prefix_length = [16]u8{ 2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4 };
pub const code_length_prefix_value = [16]u8{ 0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5 };

// ---------------------------------------------------------------------------
// Block-length prefix ranges (RFC 7932). offset + [0, 2^nbits).
pub const PrefixRange = struct { offset: u32, nbits: u8 };
pub const block_length_ranges = [num_block_len_symbols]PrefixRange{
    .{ .offset = 1, .nbits = 2 },     .{ .offset = 5, .nbits = 2 },
    .{ .offset = 9, .nbits = 2 },     .{ .offset = 13, .nbits = 2 },
    .{ .offset = 17, .nbits = 3 },    .{ .offset = 25, .nbits = 3 },
    .{ .offset = 33, .nbits = 3 },    .{ .offset = 41, .nbits = 3 },
    .{ .offset = 49, .nbits = 4 },    .{ .offset = 65, .nbits = 4 },
    .{ .offset = 81, .nbits = 4 },    .{ .offset = 97, .nbits = 4 },
    .{ .offset = 113, .nbits = 5 },   .{ .offset = 145, .nbits = 5 },
    .{ .offset = 177, .nbits = 5 },   .{ .offset = 209, .nbits = 5 },
    .{ .offset = 241, .nbits = 6 },   .{ .offset = 305, .nbits = 6 },
    .{ .offset = 369, .nbits = 7 },   .{ .offset = 497, .nbits = 8 },
    .{ .offset = 753, .nbits = 9 },   .{ .offset = 1265, .nbits = 10 },
    .{ .offset = 2289, .nbits = 11 }, .{ .offset = 4337, .nbits = 12 },
    .{ .offset = 8433, .nbits = 13 }, .{ .offset = 16625, .nbits = 24 },
};

// ---------------------------------------------------------------------------
// Command (insert-and-copy) LUT — generated per google/brotli prefix.c.
pub const CmdLutElement = struct {
    insert_len_extra_bits: u8,
    copy_len_extra_bits: u8,
    distance_code: i8, // 0 (implicit distance) or -1 (read a distance code)
    context: u8, // distance context id
    insert_len_offset: u16,
    copy_len_offset: u16,
};

const insert_length_extra_bits = [24]u8{
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
};
const copy_length_extra_bits = [24]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24,
};
const cell_pos = [11]u8{ 0, 1, 0, 1, 8, 9, 2, 16, 10, 17, 18 };

pub const cmd_lut: [num_command_symbols]CmdLutElement = blk: {
    @setEvalBranchQuota(20000);
    var insert_off: [24]u16 = undefined;
    var copy_off: [24]u16 = undefined;
    insert_off[0] = 0;
    copy_off[0] = 2;
    var i: usize = 0;
    while (i < 23) : (i += 1) {
        insert_off[i + 1] = insert_off[i] + (@as(u16, 1) << @intCast(insert_length_extra_bits[i]));
        copy_off[i + 1] = copy_off[i] + (@as(u16, 1) << @intCast(copy_length_extra_bits[i]));
    }
    var lut: [num_command_symbols]CmdLutElement = undefined;
    var sym: usize = 0;
    while (sym < num_command_symbols) : (sym += 1) {
        const cell_idx = sym >> 6;
        const pos = cell_pos[cell_idx];
        const copy_code = ((@as(usize, pos) << 3) & 0x18) + (sym & 0x7);
        const cpy_off = copy_off[copy_code];
        const insert_code = (@as(usize, pos) & 0x18) + ((sym >> 3) & 0x7);
        lut[sym] = .{
            .copy_len_extra_bits = copy_length_extra_bits[copy_code],
            .context = if (cpy_off > 4) 3 else @intCast(cpy_off - 2),
            .copy_len_offset = cpy_off,
            .distance_code = if (cell_idx >= 2) -1 else 0,
            .insert_len_extra_bits = insert_length_extra_bits[insert_code],
            .insert_len_offset = insert_off[insert_code],
        };
    }
    break :blk lut;
};

// ---------------------------------------------------------------------------
// Context lookup table (2048 bytes): context = lut[p1] | lut[256 + p2],
// where lut = &table[mode << 9]. Modes: 0=LSB6, 1=MSB6, 2=UTF8, 3=SIGNED.
fn rep(comptime v: u8, comptime n: usize) [n]u8 {
    return [_]u8{v} ** n;
}

const lsb6_last: [256]u8 = blk: {
    var a: [256]u8 = undefined;
    for (0..256) |i| a[i] = @intCast(i & 63);
    break :blk a;
};
const msb6_last: [256]u8 = blk: {
    var a: [256]u8 = undefined;
    for (0..256) |i| a[i] = @intCast(i >> 2);
    break :blk a;
};
const zeros256 = rep(0, 256);

const utf8_last: [256]u8 = // stylua: ignore
    [_]u8{
        0,  0,  0,  0,  0,  0,  0,  0,  0,  4,  4,  0,  0,  4,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        8,  12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
        44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
        12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
        52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
        12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
        60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    } ++ (.{ 0, 1 } ** 32) ++ (.{ 2, 3 } ** 32);

const utf8_second: [256]u8 = // stylua: ignore
    [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
        1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
        1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
    } ++ rep(0, 64) ++ rep(0, 16) ++ rep(2, 48);

const signed_last: [256]u8 =
    [_]u8{ 0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8 } ++
    rep(16, 48) ++ rep(24, 64) ++ rep(32, 64) ++ rep(40, 48) ++
    rep(48, 15) ++ [_]u8{56};

const signed_second: [256]u8 =
    [_]u8{ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 } ++
    rep(2, 48) ++ rep(3, 64) ++ rep(4, 64) ++ rep(5, 48) ++
    rep(6, 15) ++ [_]u8{7};

pub const context_lookup: [2048]u8 =
    lsb6_last ++ zeros256 ++
    msb6_last ++ zeros256 ++
    utf8_last ++ utf8_second ++
    signed_last ++ signed_second;

comptime {
    if (context_lookup.len != 2048) @compileError("context_lookup must be 2048 bytes");
}
