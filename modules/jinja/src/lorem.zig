// SPDX-License-Identifier: MIT
//! `lipsum()`: Jinja2's `generate_lorem_ipsum` (word list and algorithm of
//! `jinja2/constants.py` and `jinja2/utils.py`, BSD-3-Clause), driven by the
//! render's seeded PRNG instead of Python's global `random`.

const std = @import("std");

pub const words = [_][]const u8{
    "a",          "ac",        "accumsan",     "ad",        "adipiscing",   "aenean",      "aliquam",     "aliquet",   "amet",        "ante",      "aptent",
    "arcu",       "at",        "auctor",       "augue",     "bibendum",     "blandit",     "class",       "commodo",   "condimentum", "congue",    "consectetuer",
    "consequat",  "conubia",   "convallis",    "cras",      "cubilia",      "cum",         "curabitur",   "curae",     "cursus",      "dapibus",   "diam",
    "dictum",     "dictumst",  "dignissim",    "dis",       "dolor",        "donec",       "dui",         "duis",      "egestas",     "eget",      "eleifend",
    "elementum",  "elit",      "enim",         "erat",      "eros",         "est",         "et",          "etiam",     "eu",          "euismod",   "facilisi",
    "facilisis",  "fames",     "faucibus",     "felis",     "fermentum",    "feugiat",     "fringilla",   "fusce",     "gravida",     "habitant",  "habitasse",
    "hac",        "hendrerit", "hymenaeos",    "iaculis",   "id",           "imperdiet",   "in",          "inceptos",  "integer",     "interdum",  "ipsum",
    "justo",      "lacinia",   "lacus",        "laoreet",   "lectus",       "leo",         "libero",      "ligula",    "litora",      "lobortis",  "lorem",
    "luctus",     "maecenas",  "magna",        "magnis",    "malesuada",    "massa",       "mattis",      "mauris",    "metus",       "mi",        "molestie",
    "mollis",     "montes",    "morbi",        "mus",       "nam",          "nascetur",    "natoque",     "nec",       "neque",       "netus",     "nibh",
    "nisi",       "nisl",      "non",          "nonummy",   "nostra",       "nulla",       "nullam",      "nunc",      "odio",        "orci",      "ornare",
    "parturient", "pede",      "pellentesque", "penatibus", "per",          "pharetra",    "phasellus",   "placerat",  "platea",      "porta",     "porttitor",
    "posuere",    "potenti",   "praesent",     "pretium",   "primis",       "proin",       "pulvinar",    "purus",     "quam",        "quis",      "quisque",
    "rhoncus",    "ridiculus", "risus",        "rutrum",    "sagittis",     "sapien",      "scelerisque", "sed",       "sem",         "semper",    "senectus",
    "sit",        "sociis",    "sociosqu",     "sodales",   "sollicitudin", "suscipit",    "suspendisse", "taciti",    "tellus",      "tempor",    "tempus",
    "tincidunt",  "torquent",  "tortor",       "tristique", "turpis",       "ullamcorper", "ultrices",    "ultricies", "urna",        "ut",        "varius",
    "vehicula",   "vel",       "velit",        "venenatis", "vestibulum",   "vitae",       "vivamus",     "viverra",   "volutpat",    "vulputate",
};

pub const Error = error{ OutOfMemory, BadArgument };

/// `n` paragraphs of `min`..`max` words (`max` exclusive, as `randrange`).
/// With `html` each is wrapped in `<p>…</p>` and joined by a newline, else
/// the paragraphs are joined by a blank line.
pub fn generate(arena: std.mem.Allocator, rng: std.Random, n: usize, html: bool, min: i64, max: i64) Error![]u8 {
    if (min < 0 or max <= min) return error.BadArgument;
    var out: std.ArrayList(u8) = .empty;
    for (0..n) |pi| {
        if (pi != 0) try out.appendSlice(arena, if (html) "\n" else "\n\n");
        if (html) try out.appendSlice(arena, "<p>");
        var next_capitalized = true;
        var last_comma: i64 = 0;
        var last_fullstop: i64 = 0;
        var last: ?[]const u8 = null;
        const count: i64 = min + @as(i64, @intCast(rng.uintLessThan(u64, @intCast(max - min))));
        var idx: i64 = 0;
        var first = true;
        var end_char: u8 = ' ';
        while (idx < count) : (idx += 1) {
            var word: []const u8 = undefined;
            while (true) {
                word = words[rng.uintLessThan(usize, words.len)];
                if (last == null or !std.mem.eql(u8, word, last.?)) {
                    last = word;
                    break;
                }
            }
            if (!first) try out.append(arena, ' ');
            first = false;
            if (next_capitalized) {
                try out.append(arena, std.ascii.toUpper(word[0]));
                try out.appendSlice(arena, word[1..]);
                next_capitalized = false;
            } else try out.appendSlice(arena, word);
            end_char = word[word.len - 1];
            // Commas, then the end of a sentence, as the reference decides them.
            if (idx - @as(i64, @intCast(3 + rng.uintLessThan(u64, 5))) > last_comma) {
                last_comma = idx;
                last_fullstop += 2;
                try out.append(arena, ',');
                end_char = ',';
            }
            if (idx - @as(i64, @intCast(10 + rng.uintLessThan(u64, 10))) > last_fullstop) {
                last_comma = idx;
                last_fullstop = idx;
                try out.append(arena, '.');
                end_char = '.';
                next_capitalized = true;
            }
        }
        // The paragraph ends with a dot.
        if (end_char == ',') out.items[out.items.len - 1] = '.' else if (end_char != '.') try out.append(arena, '.');
        if (html) try out.appendSlice(arena, "</p>");
    }
    return out.items;
}

test "lipsum: paragraph shape, determinism and bounds" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var p1: std.Random.DefaultPrng = .init(7);
    var p2: std.Random.DefaultPrng = .init(7);
    const a = try generate(arena.allocator(), p1.random(), 3, true, 20, 100);
    const b = try generate(arena.allocator(), p2.random(), 3, true, 20, 100);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, a, "<p>"));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, a, "\n"));
    var it = std.mem.splitSequence(u8, a, "\n");
    while (it.next()) |para| {
        try std.testing.expect(std.mem.startsWith(u8, para, "<p>") and std.mem.endsWith(u8, para, ".</p>"));
        const body = para[3 .. para.len - 4];
        const w = std.mem.count(u8, body, " ") + 1;
        try std.testing.expect(w >= 20 and w < 100);
        try std.testing.expect(std.ascii.isUpper(body[0]));
        try std.testing.expect(std.mem.find(u8, body, ",.") == null);
    }
    const plain = try generate(arena.allocator(), p1.random(), 2, false, 5, 6);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, plain, "\n\n"));
    try std.testing.expect(std.mem.find(u8, plain, "<") == null);
    try std.testing.expectError(error.BadArgument, generate(arena.allocator(), p1.random(), 1, true, 5, 5));
    const none = try generate(arena.allocator(), p1.random(), 0, true, 1, 2);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}
