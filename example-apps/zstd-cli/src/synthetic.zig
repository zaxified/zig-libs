// SPDX-License-Identifier: BSD-3-Clause AND MIT
//! The synthetic inputs of `zstd -b` without a file: libzstd 1.5.7's
//! `programs/lorem.c` (the default: lorem ipsum text) and
//! `programs/datagen.c` (`-P#`: data of a given compressibility), byte
//! for byte, so that the benchmark's sizes and ratios are the C command's.

const std = @import("std");

// ------------------------------------------------------------------ lorem

const words = [_][]const u8{
    "lorem",        "ipsum",      "dolor",       "sit",          "amet",
    "consectetur",  "adipiscing", "elit",        "sed",          "do",
    "eiusmod",      "tempor",     "incididunt",  "ut",           "labore",
    "et",           "dolore",     "magna",       "aliqua",       "dis",
    "lectus",       "vestibulum", "mattis",      "ullamcorper",  "velit",
    "commodo",      "a",          "lacus",       "arcu",         "magnis",
    "parturient",   "montes",     "nascetur",    "ridiculus",    "mus",
    "mauris",       "nulla",      "malesuada",   "pellentesque", "eget",
    "gravida",      "in",         "dictum",      "non",          "erat",
    "nam",          "voluptat",   "maecenas",    "blandit",      "aliquam",
    "etiam",        "enim",       "lobortis",    "scelerisque",  "fermentum",
    "dui",          "faucibus",   "ornare",      "at",           "elementum",
    "eu",           "facilisis",  "odio",        "morbi",        "quis",
    "eros",         "donec",      "ac",          "orci",         "purus",
    "turpis",       "cursus",     "leo",         "vel",          "porta",
    "consequat",    "interdum",   "varius",      "vulputate",    "aliquet",
    "pharetra",     "nunc",       "auctor",      "urna",         "id",
    "metus",        "viverra",    "nibh",        "cras",         "mi",
    "unde",         "omnis",      "iste",        "natus",        "error",
    "perspiciatis", "voluptatem", "accusantium", "doloremque",   "laudantium",
    "totam",        "rem",        "aperiam",     "eaque",        "ipsa",
    "quae",         "ab",         "illo",        "inventore",    "veritatis",
    "quasi",        "architecto", "beatae",      "vitae",        "dicta",
    "sunt",         "explicabo",  "nemo",        "ipsam",        "quia",
    "voluptas",     "aspernatur", "aut",         "odit",         "fugit",
    "consequuntur", "magni",      "dolores",     "eos",          "qui",
    "ratione",      "sequi",      "nesciunt",    "neque",        "porro",
    "quisquam",     "est",        "dolorem",     "adipisci",     "numquam",
    "eius",         "modi",       "tempora",     "incidunt",     "magnam",
    "quaerat",      "ad",         "minima",      "veniam",       "nostrum",
    "ullam",        "corporis",   "suscipit",    "laboriosam",   "nisi",
    "aliquid",      "ex",         "ea",          "commodi",      "consequatur",
    "autem",        "eum",        "iure",        "voluptate",    "esse",
    "quam",         "nihil",      "molestiae",   "illum",        "fugiat",
    "quo",          "pariatur",   "vero",        "accusamus",    "iusto",
    "dignissimos",  "ducimus",    "blanditiis",  "praesentium",  "voluptatum",
    "deleniti",     "atque",      "corrupti",    "quos",         "quas",
    "molestias",    "excepturi",  "sint",        "occaecati",    "cupiditate",
    "provident",    "similique",  "culpa",       "officia",      "deserunt",
    "mollitia",     "animi",      "laborum",     "dolorum",      "fuga",
    "harum",        "quidem",     "rerum",       "facilis",      "expedita",
    "distinctio",   "libero",     "tempore",     "cum",          "soluta",
    "nobis",        "eligendi",   "optio",       "cumque",       "impedit",
    "minus",        "quod",       "maxime",      "placeat",      "facere",
    "possimus",     "assumenda",  "repellendus", "temporibus",   "quibusdam",
    "officiis",     "debitis",    "saepe",       "eveniet",      "voluptates",
    "repudiandae",  "recusandae", "itaque",      "earum",        "hic",
    "tenetur",      "sapiente",   "delectus",    "reiciendis",   "cillum",
    "maiores",      "alias",      "perferendis", "doloribus",    "asperiores",
    "repellat",     "minim",      "nostrud",     "exercitation", "ullamco",
    "laboris",      "aliquip",    "duis",        "aute",         "irure",
};

/// `kWeights`: a word of length n appears weights[min(n, 5)] times in the
/// distribution.
const weights = [_]u32{ 0, 8, 6, 4, 3, 2 };

/// `g_distrib` (`init_word_distrib`).
const distrib = blk: {
    @setEvalBranchQuota(20000);
    var total: usize = 0;
    for (words) |w| total += weights[@min(w.len, weights.len - 1)];
    var d: [total]u16 = undefined;
    var i: usize = 0;
    for (words, 0..) |w, id| {
        for (0..weights[@min(w.len, weights.len - 1)]) |_| {
            d[i] = id;
            i += 1;
        }
    }
    break :blk d;
};

/// `LOREM_genBlock`'s globals.
const Lorem = struct {
    buf: []u8,
    n: usize = 0,
    root: u32,

    /// `LOREM_rand`.
    fn rand(l: *Lorem, range: u32) u32 {
        var r = l.root;
        r *%= 2654435761;
        r ^= 2246822519;
        r = std.math.rotl(u32, r, 13);
        l.root = r;
        return @intCast((@as(u64, r) * range) >> 32);
    }

    fn about(l: *Lorem, target: u32) u32 {
        return l.rand(target) + l.rand(target) + 1;
    }

    /// `writeLastCharacters`.
    fn writeLast(l: *Lorem) void {
        const last = l.buf.len - l.n;
        if (last == 0) return;
        l.buf[l.n] = '.';
        l.n += 1;
        if (last > 2) @memset(l.buf[l.n..][0 .. last - 2], ' ');
        if (last > 1) l.buf[l.buf.len - 1] = '\n';
        l.n = l.buf.len;
    }

    fn word(l: *Lorem, w: []const u8, sep: []const u8, up: bool) void {
        if (l.n + w.len + sep.len > l.buf.len) {
            l.writeLast();
            return;
        }
        @memcpy(l.buf[l.n..][0..w.len], w);
        if (up) l.buf[l.n] -%= 'a' - 'A';
        l.n += w.len;
        @memcpy(l.buf[l.n..][0..sep.len], sep);
        l.n += sep.len;
    }

    fn sentence(l: *Lorem, nb_words: u32) void {
        const comma1 = l.about(9);
        const comma2 = comma1 + l.about(7);
        const end_sep: []const u8 = if (l.rand(11) == 7) "? " else ". ";
        for (0..nb_words) |i| {
            const w = words[distrib[l.rand(distrib.len)]];
            var sep: []const u8 = " ";
            if (i == comma1) sep = ", ";
            if (i == comma2) sep = ", ";
            if (i == nb_words - 1) sep = end_sep;
            l.word(w, sep, i == 0);
        }
    }

    fn paragraph(l: *Lorem, nb_sentences: u32) void {
        for (0..nb_sentences) |_| l.sentence(l.about(11));
        if (l.n < l.buf.len) {
            l.buf[l.n] = '\n';
            l.n += 1;
        }
        if (l.n < l.buf.len) {
            l.buf[l.n] = '\n';
            l.n += 1;
        }
    }
};

/// `LOREM_genBuffer`: `buf` filled with lorem ipsum from `seed`.
pub fn lorem(buf: []u8, seed: u32) void {
    var l: Lorem = .{ .buf = buf, .root = seed };
    // generateFirstSentence
    for (0..18) |i| l.word(words[i], if (i == 4 or i == 7) ", " else " ", i == 0);
    l.word(words[18], ". ", false);
    while (l.n < l.buf.len) l.paragraph(l.about(7));
}

// ---------------------------------------------------------------- datagen

const lt_log = 13;
const lt_size = 1 << lt_log;

/// `RDG_rand`.
fn rdgRand(src: *u32) u32 {
    var r = src.*;
    r *%= 2654435761;
    r ^= 2246822519;
    r = std.math.rotl(u32, r, 13);
    src.* = r;
    return r >> 5;
}

/// `RDG_fillLiteralDistrib`: `ld` in 24.8 fixed point.
fn fillLiteralDistrib(ldt: *[lt_size]u8, ld: u32) void {
    const first: u8 = if (ld == 0) 0 else '(';
    const last: u8 = if (ld == 0) 255 else '}';
    var c: u8 = if (ld == 0) 0 else '0';
    var u: u32 = 0;
    while (u < lt_size) {
        const weight = (((lt_size - u) *% ld) >> 8) + 1;
        const end = @min(u + weight, lt_size);
        while (u < end) : (u += 1) ldt[u] = c;
        c +%= 1;
        if (c > last) c = first;
    }
}

fn randLength(seed: *u32) u32 {
    if (rdgRand(seed) & 7 != 0) return rdgRand(seed) & 0xF;
    return (rdgRand(seed) & 0x1FF) + 0xF;
}

/// `RDG_genBuffer(buf, size, match_proba, 0.0, seed)`: literals from
/// `match_proba / 4.5`.
pub fn datagen(buf: []u8, match_proba: f64, seed_in: u32) void {
    var seed = seed_in;
    var ldt: [lt_size]u8 = @splat('0');
    const lit_proba = match_proba / 4.5;
    fillLiteralDistrib(&ldt, @intFromFloat(lit_proba * 256 + 0.001));
    // RDG_genBlock, no prefix
    const match_proba32: u32 = @intFromFloat(32768 * match_proba);
    var pos: usize = 0;
    var prev_offset: u32 = 1;
    if (match_proba >= 1.0) {
        while (true) {
            var size0: usize = rdgRand(&seed) & 3;
            size0 = @as(usize, 1) << @intCast(16 + size0 * 2);
            size0 += rdgRand(&seed) & (size0 - 1);
            if (buf.len < pos + size0) {
                @memset(buf[pos..], 0);
                return;
            }
            @memset(buf[pos..][0..size0], 0);
            pos += size0;
            buf[pos - 1] = ldt[rdgRand(&seed) & (lt_size - 1)];
        }
    }
    if (pos == 0 and buf.len > 0) {
        buf[0] = ldt[rdgRand(&seed) & (lt_size - 1)];
        pos = 1;
    }
    while (pos < buf.len) {
        if (rdgRand(&seed) & 0x7FFF < match_proba32) {
            const length = randLength(&seed) + 4;
            const d = @min(pos + length, buf.len);
            const repeat = rdgRand(&seed) & 15 == 2;
            const rand_offset = (rdgRand(&seed) & 0x7FFF) + 1;
            const offset: u32 = if (repeat) prev_offset else @intCast(@min(rand_offset, pos));
            var match = pos - offset;
            while (pos < d) : ({
                pos += 1;
                match += 1;
            }) buf[pos] = buf[match];
            prev_offset = offset;
        } else {
            const length = randLength(&seed);
            const d = @min(pos + length, buf.len);
            while (pos < d) : (pos += 1) buf[pos] = ldt[rdgRand(&seed) & (lt_size - 1)];
        }
    }
}
