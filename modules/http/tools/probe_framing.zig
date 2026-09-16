// SPDX-License-Identifier: MIT
//
// WHAT THIS ASKS. Which line endings does the HTTP/1.1 framing layer accept,
// and is anything unbounded behind them? Four questions:
//
//   F1. Which blank-line spellings terminate a request HEAD? A bare LF that
//       ends the head where a peer expects CRLF is a request-smuggling desync.
//   F2. Which line endings does the CHUNK framing tolerate — in the size line,
//       after the data, in the terminator?
//   F3. Is the TRAILER section bounded? Trailers are read off the wire after
//       the body, and `max_body_bytes` does not cover them.
//   F4. Which authority shapes does `isValidHost` accept? Informational: this
//       is a judgement table, printed for a human, asserted on by nobody.
//
// WHY THIS IS A PROBE AND NOT A UNIT TEST. F1–F3 are TABLES: the interesting
// output is the whole grid of spellings against outcomes, which is how you see
// that one row differs from its neighbours. The module's own tests pin the
// individual rulings (see `h1.zig`'s "bare LF anywhere in chunk framing is
// rejected" and the trailer-cap tests); this prints the shape they came from.
// F3 additionally allocates an 8 MB wire, which no unit test should do.
//
// WHAT IT PRODUCES. The grid, plus a verdict. Exit non-zero if a CONTROL stops
// working (the canonical CRLF spelling must always work — otherwise the probe
// is broken, not the module) or if a REGRESSION appears (a bare-LF spelling
// silently accepted, or an unbounded trailer section).
//
// HISTORY, because the expectations here are inverted from how they started.
// On 2026-09-04 this probe found both: a bare LF silently ended the head, the
// chunk trailer and the post-chunk CRLF (A1 http F4), and the trailer section
// was unbounded — 200 000 trailer lines were consumed off the wire behind a
// 5-byte body (A1 http F5). Commit `f0ee5ddd` closed both: bare LF is now
// rejected everywhere in framing, and `ChunkedReader.max_trailer_bytes`
// (default 32 KiB) is enforced even when trailers are not captured at all,
// with a new `FailReason.trailer_too_large`. So today every one of those rows
// is expected to REFUSE, and this file is a regression detector for that fix.
//
//     zig build-exe -OReleaseSafe --dep http -Mroot=probe_framing.zig \
//       --dep netaddr --dep datefmt -Mhttp=../src/root.zig \
//       -Mnetaddr=../../netaddr/src/root.zig -Mdatefmt=../../datefmt/src/root.zig
const std = @import("std");
const http = @import("http");
const h1 = http.h1;

var failures: u32 = 0;

fn fail(comptime fmt: []const u8, args: anytype) void {
    failures += 1;
    std.debug.print("  ⛔ " ++ fmt ++ "\n", args);
}

// ── F1. head terminators ────────────────────────────────────────────────────

const HeadCase = struct {
    name: []const u8,
    wire: []const u8,
    /// The canonical spelling is the CONTROL: it must keep working.
    control: bool = false,
};

fn probeHeads() void {
    const cases = [_]HeadCase{
        .{ .name = "CRLF CRLF (canonical)", .wire = "GET / HTTP/1.1\r\nHost: a\r\n\r\nSMUGGLED", .control = true },
        .{ .name = "CRLF LF (bare-LF terminator)", .wire = "GET / HTTP/1.1\r\nHost: a\r\n\nSMUGGLED" },
        .{ .name = "CRLF CR CR LF", .wire = "GET / HTTP/1.1\r\nHost: a\r\n\r\r\nSMUGGLED" },
        .{ .name = "CRLF CR CR CR LF", .wire = "GET / HTTP/1.1\r\nHost: a\r\n\r\r\r\nSMUGGLED" },
    };
    std.debug.print("── F1: which blank-line spellings terminate the head ──\n", .{});
    for (cases) |c| {
        var buf: [4096]u8 = undefined;
        var r: std.Io.Reader = .fixed(c.wire);
        const head = h1.readHead(&r, &buf) catch |e| {
            std.debug.print("  {s:34} readHead REFUSED ({s})\n", .{ c.name, @errorName(e) });
            if (c.control) fail("{s}: the CONTROL was refused — the probe is broken, not the module", .{c.name});
            continue;
        };
        const left = r.buffered();
        const parsed = h1.RequestHead.parse(head);
        const smuggled = std.mem.indexOf(u8, left, "SMUGGLED") != null;
        std.debug.print("  {s:34} head={d:>3}B leftover=\"{s}\" parse={s}\n", .{
            c.name, head.len, left, if (parsed) |_| "OK" else |e| @errorName(e),
        });
        if (c.control) {
            if (!smuggled) fail("{s}: the CONTROL did not leave the next bytes unread — probe broken", .{c.name});
        } else if (smuggled) {
            // `readHead` SUCCEEDED on a non-canonical spelling and left the
            // rest of the wire unread — that is the desync, whether or not the
            // head it returned goes on to parse.
            fail("{s}: a non-canonical terminator ENDED the head — A1 http F4 is back", .{c.name});
        }
    }
    std.debug.print("\n", .{});
}

// ── F2. chunk framing ───────────────────────────────────────────────────────

const ChunkCase = struct {
    name: []const u8,
    wire: []const u8,
    control: bool = false,
    /// A bare LF somewhere in the framing: must NOT decode cleanly.
    bare_lf: bool = false,
};

fn probeChunks() void {
    const cases = [_]ChunkCase{
        .{ .name = "canonical CRLF everywhere", .wire = "5\r\nhello\r\n0\r\n\r\n", .control = true },
        .{ .name = "chunk-size line bare LF", .wire = "5\nhello\r\n0\r\n\r\n", .bare_lf = true },
        .{ .name = "post-data terminator bare LF", .wire = "5\r\nhello\n0\r\n\r\n", .bare_lf = true },
        .{ .name = "everything bare LF", .wire = "5\nhello\n0\n\n", .bare_lf = true },
        .{ .name = "size line CR CR LF", .wire = "5\r\r\nhello\r\n0\r\n\r\n" },
        .{ .name = "post-data CR CR CR LF", .wire = "5\r\nhello\r\r\r\n0\r\n\r\n" },
        .{ .name = "size with trailing SP (5 )", .wire = "5 \r\nhello\r\n0\r\n\r\n" },
        .{ .name = "size with leading SP ( 5)", .wire = " 5\r\nhello\r\n0\r\n\r\n" },
        .{ .name = "size 0x5", .wire = "0x5\r\nhello\r\n0\r\n\r\n" },
        .{ .name = "size +5", .wire = "+5\r\nhello\r\n0\r\n\r\n" },
        .{ .name = "size 05 (leading zero)", .wire = "05\r\nhello\r\n0\r\n\r\n" },
        .{ .name = "size 0000000000000005 (16 dig)", .wire = "0000000000000005\r\nhello\r\n0\r\n\r\n" },
        .{ .name = "size 00000000000000005 (17)", .wire = "00000000000000005\r\nhello\r\n0\r\n\r\n" },
        .{ .name = "chunk-ext ;a=b", .wire = "5;a=b\r\nhello\r\n0\r\n\r\n" },
        .{ .name = "last-chunk with ext", .wire = "5\r\nhello\r\n0;x=y\r\n\r\n" },
    };
    std.debug.print("── F2: chunk framing line endings the decoder tolerates ──\n", .{});
    for (cases) |c| {
        var out: [4096]u8 = undefined;
        var r: std.Io.Reader = .fixed(c.wire);
        var cbuf: [512]u8 = undefined;
        var cr = h1.ChunkedReader.init(&r, &cbuf);
        var w: std.Io.Writer = .fixed(&out);
        var err: ?[]const u8 = null;
        _ = cr.reader.streamRemaining(&w) catch |e| blk: {
            err = @errorName(e);
            break :blk 0;
        };
        const body = out[0..w.end];
        const clean = err == null and std.mem.eql(u8, body, "hello");
        std.debug.print("  {s:32} body=\"{s}\" err={s} reason={s}\n", .{
            c.name,                                       body, err orelse "-",
            if (cr.fail_reason) |x| @tagName(x) else "-",
        });
        if (c.control and !clean) {
            fail("{s}: the CONTROL did not decode — the probe is broken, not the module", .{c.name});
        }
        if (c.bare_lf and clean) {
            fail("{s}: a bare LF decoded CLEANLY — A1 http F4 is back", .{c.name});
        }
    }
    std.debug.print("\n", .{});
}

// ── F3. is the trailer section bounded? ─────────────────────────────────────

fn probeTrailerBound(gpa: std.mem.Allocator) !void {
    std.debug.print("── F3: the trailer section behind a 5-byte body ──\n", .{});
    // A chunked message whose BODY is 5 bytes and whose trailer section is
    // enormous. `max_body_bytes` does not reach trailers; before f0ee5ddd
    // nothing did.
    const lines = 200_000;
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try wire.appendSlice(gpa, "5\r\nhello\r\n0\r\n");
    for (0..lines) |_| try wire.appendSlice(gpa, "X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    try wire.appendSlice(gpa, "\r\n");
    const trailer_wire = wire.items.len - "5\r\nhello\r\n".len;

    var out: [64]u8 = undefined;
    var r: std.Io.Reader = .fixed(wire.items);
    var cbuf: [512]u8 = undefined;
    // No capture buffer at all: the cap must bind even when trailers are
    // DISCARDED, which is the default and was the hole.
    var cr = h1.ChunkedReader.init(&r, &cbuf);
    var w: std.Io.Writer = .fixed(&out);
    var err: ?[]const u8 = null;
    _ = cr.reader.streamRemaining(&w) catch |e| blk: {
        err = @errorName(e);
        break :blk 0;
    };
    // ⚠ Report what actually REACHED THE SINK, not the call's return value: on
    // the failure path that value is this catch block's own `0`, and printing
    // it would put a fabricated "0 B delivered" where a measurement belongs.
    const n = w.end;
    std.debug.print("  cap={d} B, trailer section offered={d} B ({d} lines)\n", .{
        cr.max_trailer_bytes, trailer_wire, lines,
    });
    std.debug.print("  body delivered={d} B  err={s}  reason={s}  seen={d} B  overflow={}\n", .{
        n,                                            err orelse "-",
        if (cr.fail_reason) |x| @tagName(x) else "-", cr.trailer_bytes_seen,
        cr.trailers_overflow,
    });
    if (cr.fail_reason == null and err == null) {
        fail("the trailer section was consumed WITHOUT a cap — A1 http F5 is back ({d} B behind a {d} B body)", .{ trailer_wire, n });
    } else if (cr.trailer_bytes_seen > cr.max_trailer_bytes + 4096) {
        fail("the cap bound late: {d} B seen against a {d} B cap", .{ cr.trailer_bytes_seen, cr.max_trailer_bytes });
    }
    std.debug.print("\n", .{});
}

// ── F4. authority shapes (informational) ────────────────────────────────────

fn probeHosts() void {
    std.debug.print("── F4: isValidHost, printed for a human (no assertion) ──\n", .{});
    const cases = [_][]const u8{
        "example.com",      "example.com:8080", "[::1]:80",     "u@evil.com",
        "example.com/path", "a,b",              "example.com ", "",
        "%2f",              "a;b",              "a=b",          "*",
        "!$&'()*+;=",       "999999999999999",  "a:1:2:3",      "a:70000",
        "a:-1",             "[::1",             "exa mple.com", "exam\tple",
        "exámple.com",
        "a..b",             "..",               "a:",
    };
    for (cases) |c| std.debug.print("  isValidHost(\"{s}\") = {}\n", .{ c, h1.isValidHost(c) });
    std.debug.print("\n", .{});
}

pub fn main() !void {
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg.deinit();
    const gpa = dbg.allocator();
    std.debug.print("optimize mode = {s}\n\n", .{@tagName(@import("builtin").mode)});

    probeHeads();
    probeChunks();
    try probeTrailerBound(gpa);
    probeHosts();

    if (failures != 0) {
        std.debug.print("⛔ {d} problem(s) — see the lines above.\n", .{failures});
        std.process.exit(1);
    }
    std.debug.print("✅ controls work, no bare-LF spelling is accepted, the trailer section is bounded.\n", .{});
}
