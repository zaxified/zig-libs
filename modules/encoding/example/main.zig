// SPDX-License-Identifier: MIT

//! What a legacy-broker-export consumer does with `encoding`: parse a
//! declared code page name off a config line, decode legacy bytes to UTF-8
//! and encode back, both cross-checked byte-for-byte against `iconv` output
//! captured from this machine, and observe the module's documented
//! never-traps behavior where a real transcoder (`iconv`) would hard-fail.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const encoding = @import("encoding");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A config line naming the code page, the way it would arrive from an
    // ini/csv header.
    const enc = encoding.Encoding.parse("cp1250").?;
    std.debug.print("parsed alias \"cp1250\" -> {s}\n", .{enc.canonicalName()});

    // "Příliš žluťoučký kůň" (Czech pangram), UTF-8. Cross-checked against
    // `iconv -f UTF-8 -t WINDOWS-1250` on this machine, which produces this
    // exact byte string.
    const utf8_src = "P\u{0159}\u{00ed}li\u{0161} \u{017e}lu\u{0165}ou\u{010d}k\u{00fd} k\u{016f}\u{0148}";
    const iconv_windows1250 = [_]u8{
        0x50, 0xf8, 0xed, 0x6c, 0x69, 0x9a, 0x20, 0x9e,
        0x6c, 0x75, 0x9d, 0x6f, 0x75, 0xe8, 0x6b, 0xfd,
        0x20, 0x6b, 0xf9, 0xf2,
    };
    const encoded = try encoding.encodeFromUtf8(gpa, utf8_src, enc);
    defer gpa.free(encoded);
    std.debug.assert(std.mem.eql(u8, encoded, &iconv_windows1250));
    std.debug.print("encodeFromUtf8(.windows_1250): {d} bytes, matches iconv byte-exact\n", .{encoded.len});

    // Round-trip back to UTF-8.
    const decoded = try encoding.decodeToUtf8(gpa, encoded, enc);
    defer gpa.free(decoded);
    std.debug.assert(std.mem.eql(u8, decoded, utf8_src));
    std.debug.print("decodeToUtf8(.windows_1250): round-trips to the original UTF-8\n", .{});

    // Latin-1: "café", cross-checked against `iconv -f UTF-8 -t ISO-8859-1`
    // on this machine (63 61 66 e9).
    const cafe_utf8 = "caf\u{00e9}";
    const iconv_latin1 = [_]u8{ 0x63, 0x61, 0x66, 0xe9 };
    const cafe_enc = try encoding.encodeFromUtf8(gpa, cafe_utf8, .iso_8859_1);
    defer gpa.free(cafe_enc);
    std.debug.assert(std.mem.eql(u8, cafe_enc, &iconv_latin1));
    std.debug.print("encodeFromUtf8(.iso_8859_1) \"caf\\u00e9\": matches iconv byte-exact\n", .{});

    // README: "Data-lenient — never traps... a codepoint with no
    // representation in the target page becomes '?'." This module's encode
    // has no content error to name (only OutOfMemory) — it is
    // near-infallible by design, so the negative case here is the
    // documented *effect*, contrasted against what a real transcoder does:
    // `iconv -f UTF-8 -t WINDOWS-1250` on two Japanese characters
    // ("\xe6\x97\xa5\xe6\x9c\xac") exits 1 with "illegal input sequence" —
    // it refuses. This module instead substitutes '?' and always succeeds.
    const unrepresentable_utf8 = "\u{65e5}\u{672c}"; // "日本" - not in windows-1250
    const substituted = try encoding.encodeFromUtf8(gpa, unrepresentable_utf8, .windows_1250);
    defer gpa.free(substituted);
    std.debug.assert(std.mem.eql(u8, substituted, "??"));
    std.debug.print("encodeFromUtf8(.windows_1250) on non-representable text -> \"??\" (iconv would hard-fail here; this API never traps)\n", .{});
}
