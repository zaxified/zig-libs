//! RFC 7932 Appendix B — the normative Brotli word-transform table.
//!
//! Data transcribed verbatim from RFC 7932 Appendix B (identical to
//! google/brotli `c/common/transform.c`, MIT-licensed). The standard RFC 7932
//! transform set contains 121 transforms and uses no SHIFT parameters.

/// prefix/suffix pool: each id addresses a length-prefixed byte string
/// (first byte = length, then that many bytes). Trailing NUL is the empty id.
pub const prefix_suffix =
    "\x01 \x02, \x08 of the \x04 of \x02s \x01.\x05 and \x04 " ++
    "in \x01\"\x04 to \x02\">\x01\n\x02. \x01]\x05 for \x03 a \x06 " ++
    "that \x01'\x06 with \x06 from \x04 by \x01(\x06. T" ++
    "he \x04 on \x04 as \x04 is \x04ing \x02\n\t\x01:\x03ed " ++
    "\x02=\"\x04 at \x03ly \x01,\x02='\x05.com/\x07. This \x05" ++
    " not \x03er \x03al \x04ful \x04ive \x05less \x04es" ++
    "t \x04ize \x02\xc2\xa0\x04ous \x05 the \x02e \x00";

comptime {
    if (prefix_suffix.len != 217) @compileError("brotli prefix_suffix must be 217 bytes");
}

pub const prefix_suffix_map = [50]u16{
    0x00, 0x02, 0x05, 0x0E, 0x13, 0x16, 0x18, 0x1E, 0x23, 0x25,
    0x2A, 0x2D, 0x2F, 0x32, 0x34, 0x3A, 0x3E, 0x45, 0x47, 0x4E,
    0x55, 0x5A, 0x5C, 0x63, 0x68, 0x6D, 0x72, 0x77, 0x7A, 0x7C,
    0x80, 0x83, 0x88, 0x8C, 0x8E, 0x91, 0x97, 0x9F, 0xA5, 0xA9,
    0xAD, 0xB2, 0xB7, 0xBD, 0xC2, 0xC7, 0xCA, 0xCF, 0xD5, 0xD8,
};

// Transform type codes (RFC 7932 Appendix B).
const ID = 0; // IDENTITY
const OL1 = 1; // OMIT_LAST_1 .. OMIT_LAST_9 == 1..9
const OL2 = 2;
const OL3 = 3;
const OL4 = 4;
const OL5 = 5;
const OL6 = 6;
const OL7 = 7;
const OL8 = 8;
const OL9 = 9;
const UF = 10; // UPPERCASE_FIRST
const UA = 11; // UPPERCASE_ALL
const OF1 = 12; // OMIT_FIRST_1 .. OMIT_FIRST_9 == 12..20
const OF2 = 13;
const OF3 = 14;
const OF4 = 15;
const OF5 = 16;
const OF6 = 17;
const OF7 = 18;
const OF8 = 19;
const OF9 = 20;

const OMIT_LAST_9 = 9;
const UPPERCASE_FIRST = 10;
const UPPERCASE_ALL = 11;
const OMIT_FIRST_1 = 12;
const OMIT_FIRST_9 = 20;

/// Each transform is a [prefix_id, type, suffix_id] triplet (RFC 7932 App. B).
pub const transforms_data = [_]u8{
    49, ID, 49, // 0
    49, ID, 0, // 1
    0, ID, 0, // 2
    49, OF1, 49, // 3
    49, UF, 0, // 4
    49, ID, 47, // 5
    0, ID, 49, // 6
    4, ID, 0, // 7
    49, ID, 3, // 8
    49, UF, 49, // 9
    49, ID, 6, // 10
    49, OF2, 49, // 11
    49, OL1, 49, // 12
    1, ID, 0, // 13
    49, ID, 1, // 14
    0, UF, 0, // 15
    49, ID, 7, // 16
    49, ID, 9, // 17
    48, ID, 0, // 18
    49, ID, 8, // 19
    49, ID, 5, // 20
    49, ID, 10, // 21
    49, ID, 11, // 22
    49, OL3, 49, // 23
    49, ID, 13, // 24
    49, ID, 14, // 25
    49, OF3, 49, // 26
    49, OL2, 49, // 27
    49, ID, 15, // 28
    49, ID, 16, // 29
    0, UF, 49, // 30
    49, ID, 12, // 31
    5, ID, 49, // 32
    0, ID, 1, // 33
    49, OF4, 49, // 34
    49, ID, 18, // 35
    49, ID, 17, // 36
    49, ID, 19, // 37
    49, ID, 20, // 38
    49, OF5, 49, // 39
    49, OF6, 49, // 40
    47, ID, 49, // 41
    49, OL4, 49, // 42
    49, ID, 22, // 43
    49, UA, 49, // 44
    49, ID, 23, // 45
    49, ID, 24, // 46
    49, ID, 25, // 47
    49, OL7, 49, // 48
    49, OL1, 26, // 49
    49, ID, 27, // 50
    49, ID, 28, // 51
    0, ID, 12, // 52
    49, ID, 29, // 53
    49, OF9, 49, // 54
    49, OF7, 49, // 55
    49, OL6, 49, // 56
    49, ID, 21, // 57
    49, UF, 1, // 58
    49, OL8, 49, // 59
    49, ID, 31, // 60
    49, ID, 32, // 61
    47, ID, 3, // 62
    49, OL5, 49, // 63
    49, OL9, 49, // 64
    0, UF, 1, // 65
    49, UF, 8, // 66
    5, ID, 21, // 67
    49, UA, 0, // 68
    49, UF, 10, // 69
    49, ID, 30, // 70
    0, ID, 5, // 71
    35, ID, 49, // 72
    47, ID, 2, // 73
    49, UF, 17, // 74
    49, ID, 36, // 75
    49, ID, 33, // 76
    5, ID, 0, // 77
    49, UF, 21, // 78
    49, UF, 5, // 79
    49, ID, 37, // 80
    0, ID, 30, // 81
    49, ID, 38, // 82
    0, UA, 0, // 83
    49, ID, 39, // 84
    0, UA, 49, // 85
    49, ID, 34, // 86
    49, UA, 8, // 87
    49, UF, 12, // 88
    0, ID, 21, // 89
    49, ID, 40, // 90
    0, UF, 12, // 91
    49, ID, 41, // 92
    49, ID, 42, // 93
    49, UA, 17, // 94
    49, ID, 43, // 95
    0, UF, 5, // 96
    49, UA, 10, // 97
    0, ID, 34, // 98
    49, UF, 33, // 99
    49, ID, 44, // 100
    49, UA, 5, // 101
    45, ID, 49, // 102
    0, ID, 33, // 103
    49, UF, 30, // 104
    49, UA, 30, // 105
    49, ID, 46, // 106
    49, UA, 1, // 107
    49, UF, 34, // 108
    0, UF, 33, // 109
    0, UA, 30, // 110
    0, UA, 1, // 111
    49, UA, 33, // 112
    49, UA, 21, // 113
    49, UA, 12, // 114
    0, UA, 5, // 115
    49, UA, 34, // 116
    0, UA, 12, // 117
    0, UF, 30, // 118
    0, UA, 34, // 119
    0, UF, 34, // 120
};

comptime {
    if (transforms_data.len != 121 * 3) @compileError("brotli must have 121 transforms");
}

pub const num_transforms = transforms_data.len / 3;

fn prefixId(idx: usize) u8 {
    return transforms_data[idx * 3 + 0];
}
fn transformType(idx: usize) u8 {
    return transforms_data[idx * 3 + 1];
}
fn suffixId(idx: usize) u8 {
    return transforms_data[idx * 3 + 2];
}

fn toUpperCase(p: []u8) usize {
    if (p[0] < 0xC0) {
        if (p[0] >= 'a' and p[0] <= 'z') p[0] ^= 32;
        return 1;
    }
    if (p[0] < 0xE0) {
        if (p.len < 2) return 1;
        p[1] ^= 32;
        return 2;
    }
    if (p.len < 3) return p.len;
    p[2] ^= 5;
    return 3;
}

/// Apply transform `transform_idx` to a dictionary `word` of length `len`,
/// writing the transformed bytes to `dst`. Returns the number of bytes written.
/// `dst` must have room for prefix(<=5) + word + suffix(<=8) bytes.
pub fn transformWord(dst: []u8, word: []const u8, len_in: usize, transform_idx: usize) usize {
    var idx: usize = 0;
    const prefix = prefix_suffix[prefix_suffix_map[prefixId(transform_idx)]..];
    const ttype = transformType(transform_idx);
    const suffix = prefix_suffix[prefix_suffix_map[suffixId(transform_idx)]..];

    {
        const prefix_len = prefix[0];
        var k: usize = 0;
        while (k < prefix_len) : (k += 1) {
            dst[idx] = prefix[1 + k];
            idx += 1;
        }
    }

    var word_ptr = word;
    var len: usize = len_in;
    {
        if (ttype <= OMIT_LAST_9) {
            if (ttype > len) {
                len = 0;
            } else {
                len -= ttype;
            }
        } else if (ttype >= OMIT_FIRST_1 and ttype <= OMIT_FIRST_9) {
            const skip = ttype - (OMIT_FIRST_1 - 1);
            if (skip >= len) {
                word_ptr = word_ptr[len..];
                len = 0;
            } else {
                word_ptr = word_ptr[skip..];
                len -= skip;
            }
        }
        var i: usize = 0;
        while (i < len) : (i += 1) {
            dst[idx] = word_ptr[i];
            idx += 1;
        }
        if (ttype == UPPERCASE_FIRST) {
            if (len > 0) _ = toUpperCase(dst[idx - len ..][0..len]);
        } else if (ttype == UPPERCASE_ALL) {
            var rem = len;
            var off = idx - len;
            while (rem > 0) {
                const step = toUpperCase(dst[off..][0..rem]);
                off += step;
                rem -= step;
            }
        }
    }

    {
        const suffix_len = suffix[0];
        var k: usize = 0;
        while (k < suffix_len) : (k += 1) {
            dst[idx] = suffix[1 + k];
            idx += 1;
        }
    }
    return idx;
}
