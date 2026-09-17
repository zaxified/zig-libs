// SPDX-License-Identifier: MIT

//! Emits what `imap.utf7` makes of a fixed corpus, one line per input:
//! `D <hex-in> <hex-out|REJECT>` (decode) and `E <hex-in> <hex-out|REJECT>`
//! (encode), on stderr. `utf7_oracle.py` replays every line through pymap.
//!
//! WHAT IT NEEDS: nothing but this module. WHAT IT PRODUCES: the line stream
//! above; it asserts nothing itself. Build and run: see `README.md`.

const std = @import("std");
const imap = @import("imap");
const utf7 = imap.utf7;

fn emit(kind: u8, in: []const u8, res: ?[]const u8) void {
    std.debug.print("{c} ", .{kind});
    for (in) |b| std.debug.print("{x:0>2}", .{b});
    if (res) |r| {
        std.debug.print(" ", .{});
        for (r) |b| std.debug.print("{x:0>2}", .{b});
    } else std.debug.print(" REJECT", .{});
    std.debug.print("\n", .{});
}

pub fn main() !void {
    var dbg = std.heap.DebugAllocator(.{}){};
    const gpa = dbg.allocator();

    // A structured corpus: shift sequences over the modified alphabet, plus
    // literal text, plus the shapes the RFC and go-imap tables name.
    const seeds = [_][]const u8{
        "",           "abc",         "INBOX",                           "&-",         "&-abc",      "abc&-",            "a&-b&-c",
        "&AAA-",      "&AAk-",       "&AAo-",                           "&AA0-",      "&AA0ACg-",   "&ABk-",            "&AB8-",
        "&AH8-",      "&AGE-",       "&ACA-",                           "&AH4-",      "&AOk-",      "&AP8-",            "&AP8A,w-",
        "&AP8-&AP8-", "&U,BTFw-",    "~peter/mail/&U,BTFw-/&ZeVnLIqe-", "&ZeVnLIqe-", "&2A-",       "&2ADc-",           "&2ADcAAA-",
        "&AAAAHw=-",  "&AAAAHw==-",  "&/+8-",                           "&*-",        "&",          "&Jjo",             "Jjo&",
        "&Jjo&",      "&AAAAHwB,A-", "&2ADf,w-",                        "../victim",  "a/b/c",      "..",               "R&D",
        "&AC8-",      "&,,,,-",      "&AAAA-",                          "&AAAAAAAA-", "&AAE-",      "&AAI-",            "&AH-",
        "&A-",        "&AA-",        "&AAAA,,,,-",                      "\xc3\xa9",   "a\xc3\xa9b", "\xf0\x9f\x98\x80", "&2D3eAA-",
        "&AAA-&AAA-", "&AAAAAA-",    "&AAoACg-",                        "&ACY-",      "&&-",        "&-&-",
    };
    for (seeds) |s| {
        const r = utf7.decodeAlloc(gpa, s) catch {
            emit('D', s, null);
            continue;
        };
        defer gpa.free(r);
        emit('D', s, r);
    }

    // Encode direction: valid UTF-8 names.
    const names = [_][]const u8{
        "INBOX",            "INBOX/Sent",                 "R&D",  "&",        "\xc3\xa9",     "a\xc3\xa9b",
        "\xf0\x9f\x98\x80", "a\xf0\x9f\x98\x80\xc3\xa9b", "\x7f", "\x01\x02", "\r\n",         "\x00",
        "a\rb",
        "Ελληνικά",
        "почта",
        "台北/日本語",
        "~peter/mail/台北/日本語",
        "a b c",            "\x1f",                       " ",    "~",        "\xef\xbf\xbd", "\xe2\x82\xac",
    };
    for (names) |n| {
        const r = utf7.encodeAlloc(gpa, n) catch {
            emit('E', n, null);
            continue;
        };
        defer gpa.free(r);
        emit('E', n, r);
    }
}
