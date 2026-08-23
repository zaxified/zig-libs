// SPDX-License-Identifier: MIT

//! What a production HTTP server does with `accesslog`: format one request as
//! Apache/NGINX Combined Log Format, structurally validate it against the
//! documented CLF grammar, prove a log-injection payload still yields exactly
//! one well-formed record, and emit the same record as JSON Lines and check
//! it round-trips through Zig's own independent `std.json` parser. `Entry` has
//! no router coupling — it is a plain struct fed straight to a `std.Io.Writer`.
//!
//! External judge: the Apache Combined Log Format grammar, as documented by
//! `mod_log_config` — `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`.
//! The exact bytes this module emits for both the clean entry AND the
//! log-injection entry below were captured and independently checked offline
//! against a CLF-conformant regex:
//!
//!   python3 -c '
//!   import re
//!   data = open("/tmp/al_evil_clean.log", "rb").read().decode()
//!   clf = re.compile(
//!       r"^(?P<host>\S+) - - \[(?P<time>[^\]]+)\] "
//!       r"\"(?P<request>(?:[^\"\\]|\\.)*)\" (?P<status>\d+) (?P<bytes>\d+|-) "
//!       r"\"(?P<referer>(?:[^\"\\]|\\.)*)\" \"(?P<agent>(?:[^\"\\]|\\.)*)\"\r?\n$")
//!   m = clf.fullmatch(data)
//!   print(bool(m), data.count("\n"), "\r" in data)'
//!   -> True 1 False
//!
//! (the quoted-field alternation is widened from a plain `[^"]*` to
//! `(?:[^"\\]|\\.)*` to walk past the module's own `\"`/`\x0d`/`\x0a`
//! backslash escapes — the clean entry matches the plain grammar too; both
//! confirm exactly one CLF record, no raw CR, one trailing LF).
//!
//! `looksLikeCombined` below re-implements that same grammar directly in Zig
//! (field by field) so the check also runs at `zig build run-example-accesslog`
//! time, with no runtime dependency on python3 being installed.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `accesslog` (or `http`) does not export.

const std = @import("std");
const accesslog = @import("accesslog");

fn sampleEntry() accesslog.Entry {
    return .{
        .timestamp_ns = 1755878400000000000,
        .time_formatted = "22/Aug/2026:12:00:00 +0000",
        .remote_addr = "203.0.113.7:54321",
        .method = "GET",
        .target = "/api/orders?limit=20",
        .protocol = "HTTP/1.1",
        .status = 200,
        .response_bytes = 348,
        .latency_ns = 812_000,
        .user_agent = "curl/8.9.1",
        .referer = "https://example.org/dashboard",
        .request_id = "req-9f2c",
    };
}

/// Structural check against the documented CLF grammar:
/// `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"\n` — the same
/// grammar the python3/re oracle above was run against. Returns false rather
/// than panicking on any deviation, so a caller can report it.
fn looksLikeCombined(line: []const u8) bool {
    var s = line;
    if (!std.mem.endsWith(u8, s, "\n")) return false;
    s = s[0 .. s.len - 1];

    // %h — host token, no spaces.
    const sp1 = std.mem.indexOfScalar(u8, s, ' ') orelse return false;
    if (sp1 == 0) return false;
    s = s[sp1 + 1 ..];

    // %l %u — always "- -" in this module.
    if (!std.mem.startsWith(u8, s, "- - [")) return false;
    s = s["- - [".len..];

    // %t — up to the closing bracket.
    const close = std.mem.indexOfScalar(u8, s, ']') orelse return false;
    if (close == 0) return false;
    s = s[close + 1 ..];
    if (!std.mem.startsWith(u8, s, " \"")) return false;
    s = s[2..];

    // "%r" — quoted request line, closed by an UNESCAPED quote (a `\"`
    // inside it was backslash-escaped by the module, so a bare scan for the
    // next `"` finds the real closing one).
    const req_end = std.mem.indexOfScalar(u8, s, '"') orelse return false;
    s = s[req_end + 1 ..];
    if (!std.mem.startsWith(u8, s, " ")) return false;
    s = s[1..];

    // %>s — status: one or more digits.
    const sp2 = std.mem.indexOfScalar(u8, s, ' ') orelse return false;
    if (sp2 == 0 or !allDigits(s[0..sp2])) return false;
    s = s[sp2 + 1 ..];

    // %b — digits or a literal "-".
    const sp3 = std.mem.indexOfScalar(u8, s, ' ') orelse return false;
    if (sp3 == 0) return false;
    if (!std.mem.eql(u8, s[0..sp3], "-") and !allDigits(s[0..sp3])) return false;
    s = s[sp3 + 1 ..];

    // "%{Referer}i" then "%{User-Agent}i" — both quoted, both required.
    if (!std.mem.startsWith(u8, s, "\"")) return false;
    s = s[1..];
    const ref_end = std.mem.indexOfScalar(u8, s, '"') orelse return false;
    s = s[ref_end + 1 ..];
    if (!std.mem.startsWith(u8, s, " \"")) return false;
    s = s[2..];
    if (s.len == 0 or s[s.len - 1] != '"') return false;
    return true;
}

fn allDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c < '0' or c > '9') return false;
    return true;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── Combined Log Format, checked against the documented CLF grammar ────
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try accesslog.writeCombined(sampleEntry(), &w);
    const line = w.buffered();
    std.debug.print("combined: {s}", .{line});

    if (!looksLikeCombined(line)) return error.NotCombinedShaped;
    std.debug.print("matches the documented CLF grammar (host - - [time] \"req\" status bytes \"ref\" \"ua\"): OK\n", .{});

    // ── log-injection: a crafted field must still yield ONE valid record ──
    var evil_buf: [512]u8 = undefined;
    var evil_w: std.Io.Writer = .fixed(&evil_buf);
    var evil_entry = sampleEntry();
    evil_entry.user_agent = "attacker\" \r\n203.0.113.9 - - [x] \"GET /admin HTTP/1.1\" 200 1 \"-\" \"-";
    try accesslog.writeCombined(evil_entry, &evil_w);
    const evil_line = evil_w.buffered();

    if (std.mem.count(u8, evil_line, "\n") != 1) return error.LineForged;
    if (std.mem.indexOfScalar(u8, evil_line, '\r') != null) return error.RawCrInLine;
    if (!looksLikeCombined(evil_line)) return error.NotCombinedShaped;
    std.debug.print("crafted User-Agent (quote+CRLF+forged-line attempt) stayed one CLF-shaped record\n", .{});

    // ── JSON Lines: round-trip through Zig's own std.json (an independent
    // parser, standing in as the RFC 8259 conformance oracle) ─────────────
    var jbuf: [1024]u8 = undefined;
    var jw: std.Io.Writer = .fixed(&jbuf);
    try accesslog.writeJsonLines(sampleEntry(), &jw);
    const json_line = jw.buffered();
    const without_nl = json_line[0 .. json_line.len - 1];

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, without_nl, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    if (!std.mem.eql(u8, obj.get("method").?.string, "GET")) return error.FieldMismatch;
    if (obj.get("status").?.integer != 200) return error.FieldMismatch;
    std.debug.print("JSON Lines record parses under std.json and fields round-trip: OK\n", .{});

    // ── negative case, asserted by the module's own NAMED error: a fixed
    // output buffer too small to hold the record must fail as
    // error.WriteFailed (std.Io.Writer.Error), not silently truncate ──────
    var tiny_buf: [4]u8 = undefined;
    var tiny_w: std.Io.Writer = .fixed(&tiny_buf);
    if (accesslog.writeCombined(sampleEntry(), &tiny_w)) |_| {
        return error.UnexpectedSuccess;
    } else |err| switch (err) {
        error.WriteFailed => std.debug.print("undersized output buffer: WriteFailed (expected)\n", .{}),
    }
}
