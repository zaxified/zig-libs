// SPDX-License-Identifier: MIT

//! sse_parse — a client-side Server-Sent Events (WHATWG "server-sent
//! events" `text/event-stream`) line accumulator: the reusable
//! counterpart to `http.sse`, which only implements the *server* write
//! side (there is no client-side SSE consumer anywhere in the `http`
//! module or the rest of this repo). Reads lines off a `std.Io.Reader`
//! and accumulates the `event:`/`id:`/`data:`/`retry:` fields of one
//! dispatch group per the WHATWG event-stream grammar
//! (https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation),
//! returning one `Event` per blank-line-terminated group.
//!
//! Deliberate simplifications versus the full WHATWG algorithm — fine for
//! a well-behaved HTTP API like Anthropic's (which always sends
//! `Accept-Encoding: identity`, so this never has to unwrap a compressed
//! body), not a generic browser-grade parser:
//!   - Only LF (`\n`) and CRLF (`\r\n`) line endings are recognized; a
//!     lone CR terminator (no following LF) is not.
//!   - Per the spec, a dispatch with an empty data buffer is *not*
//!     delivered to the caller (its fields are discarded and reading
//!     continues) — this is what makes comment-only or id-only groups
//!     silent, matching real SSE semantics for a heartbeat `: ping\n\n`.
//!   - The "last event ID buffer" is intentionally NOT persisted across
//!     dispatch groups (the spec persists it so a group with no `id:`
//!     line still reports the previous one) — `Event.id` reports only
//!     what the *current* group set. Anthropic always sends a fresh `id`
//!     when it sends one at all, so this doesn't matter in practice and
//!     keeps `Parser` simpler (no extra persistent buffer).

const std = @import("std");

pub const Error = error{
    /// The stream ended in the middle of a dispatch group (some field
    /// lines were read but no terminating blank line arrived).
    EndOfStream,
    ReadFailed,
    /// A single line exceeded the reader's buffer capacity.
    LineTooLong,
    /// One dispatch group's joined `data:` payload exceeded
    /// `Parser.max_data_bytes` — the only bound the accumulator has on the
    /// memory a peer can make it hold (each `data:` line is bounded by the
    /// reader, the number of lines in a group was not: measured
    /// 2026-09-06, 10.0 MB of legal 4 KiB lines in one group → 2.40 GB
    /// live, and the buffer kept its capacity after the error).
    DataTooLarge,
    OutOfMemory,
};

/// One dispatched SSE event. Fields borrow from the `Parser`'s internal
/// buffers — valid until the next call to `next()` or `deinit()`.
pub const Event = struct {
    /// The `event:` type, or null (the client-side default is
    /// `"message"` — this parser reports the absence rather than
    /// filling in the default, so callers can tell the two apart).
    event: ?[]const u8 = null,
    /// The `id:` value set in this group, or null if this group set none.
    id: ?[]const u8 = null,
    /// The `data:` payload: every `data:` line in the group joined by
    /// `\n`, with the one trailing `\n` the spec adds stripped.
    data: []const u8 = "",
    /// Parsed `retry:` milliseconds, or null if absent or not a valid
    /// integer (a malformed `retry:` line is ignored, per spec).
    retry: ?u32 = null,
};

fn isAllDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// A reusable field accumulator over one live `std.Io.Reader`. Does not
/// own the reader.
pub const Parser = struct {
    reader: *std.Io.Reader,
    gpa: std.mem.Allocator,
    event_buf: std.ArrayList(u8),
    id_buf: std.ArrayList(u8),
    data_buf: std.ArrayList(u8),
    /// Whether the very first line of the stream has been through the
    /// leading-BOM check yet (WHATWG: "the leading U+FEFF BYTE ORDER MARK
    /// character, if any, must be skipped"; A1 F24). Checked once, on the
    /// first line only — a BOM mid-stream is just three odd bytes on
    /// whatever field starts with them, same as any other client.
    checked_bom: bool = false,
    /// Cap on one group's joined `data:` payload (the `\n`-joined lines,
    /// terminator included); `error.DataTooLarge` past it, and the
    /// buffers are released so the failed group's memory does not stay
    /// pinned for the parser's lifetime. Set it after `init`. The default
    /// is generous for any single API event (which is one line under the
    /// reader's own ~4 KiB line bound) and small against the 240×
    /// amplification a many-line group achieved before the cap existed.
    max_data_bytes: usize = default_max_data_bytes,

    pub const default_max_data_bytes: usize = 1 << 20;

    pub fn init(reader: *std.Io.Reader, gpa: std.mem.Allocator) Parser {
        return .{
            .reader = reader,
            .gpa = gpa,
            .event_buf = .empty,
            .id_buf = .empty,
            .data_buf = .empty,
        };
    }

    pub fn deinit(p: *Parser) void {
        p.event_buf.deinit(p.gpa);
        p.id_buf.deinit(p.gpa);
        p.data_buf.deinit(p.gpa);
        p.* = undefined;
    }

    /// Give the accumulated buffers' capacity back to `gpa`. Called on
    /// `DataTooLarge`, and available to a caller that wants an idle
    /// parser to hold nothing between events.
    pub fn releaseBuffers(p: *Parser) void {
        p.event_buf.clearAndFree(p.gpa);
        p.id_buf.clearAndFree(p.gpa);
        p.data_buf.clearAndFree(p.gpa);
    }

    /// Read and accumulate lines until a dispatch (a data-bearing group
    /// terminated by a blank line) or a clean end of stream between
    /// groups (returns null). `error.EndOfStream` means the connection
    /// closed mid-group.
    pub fn next(p: *Parser) Error!?Event {
        while (true) {
            p.event_buf.clearRetainingCapacity();
            p.id_buf.clearRetainingCapacity();
            p.data_buf.clearRetainingCapacity();
            var retry: ?u32 = null;
            var saw_line = false;

            while (true) {
                const raw_line = p.reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
                    error.EndOfStream => {
                        if (!saw_line) return null;
                        return error.EndOfStream;
                    },
                    error.StreamTooLong => return error.LineTooLong,
                    error.ReadFailed => return error.ReadFailed,
                };
                // Strip exactly the one line terminator `takeDelimiterInclusive`
                // matched — CRLF or bare LF, never more. The old
                // `trimEnd(raw_line, "\r\n")` stripped every trailing byte in
                // that set, so a value that itself ended in `\r` (legal:
                // `takeDelimiterInclusive` only recognizes `\n`, so a line
                // like `data: foo\r\r\n` is one raw line, not two) lost that
                // `\r` along with the real terminator (A1 F24).
                var line = if (raw_line.len >= 2 and raw_line[raw_line.len - 2] == '\r')
                    raw_line[0 .. raw_line.len - 2]
                else
                    raw_line[0 .. raw_line.len - 1];
                if (!p.checked_bom) {
                    p.checked_bom = true;
                    if (std.mem.startsWith(u8, line, "\xEF\xBB\xBF")) line = line[3..];
                }
                if (line.len == 0) break; // blank line: end of this group

                saw_line = true;
                if (line[0] == ':') continue; // comment line, ignored

                const colon = std.mem.indexOfScalar(u8, line, ':');
                const field = if (colon) |c| line[0..c] else line;
                var val: []const u8 = if (colon) |c| line[c + 1 ..] else "";
                if (val.len != 0 and val[0] == ' ') val = val[1..];

                if (std.mem.eql(u8, field, "event")) {
                    p.event_buf.clearRetainingCapacity();
                    try p.event_buf.appendSlice(p.gpa, val);
                } else if (std.mem.eql(u8, field, "data")) {
                    if (val.len + 1 > p.max_data_bytes - p.data_buf.items.len) {
                        p.releaseBuffers();
                        return error.DataTooLarge;
                    }
                    try p.data_buf.appendSlice(p.gpa, val);
                    try p.data_buf.append(p.gpa, '\n');
                } else if (std.mem.eql(u8, field, "id")) {
                    // A `\0` anywhere in the value invalidates the whole
                    // `id:` line per spec; keep the previously-set id (or
                    // none) instead.
                    if (std.mem.indexOfScalar(u8, val, 0) == null) {
                        p.id_buf.clearRetainingCapacity();
                        try p.id_buf.appendSlice(p.gpa, val);
                    }
                } else if (std.mem.eql(u8, field, "retry")) {
                    // Per spec the value must be all ASCII digits; anything
                    // else (including a leading `+`/`-`, which
                    // `std.fmt.parseInt` otherwise accepts) makes the whole
                    // line ignored, not merely reinterpreted (A1 F24).
                    retry = if (isAllDigits(val)) std.fmt.parseInt(u32, val, 10) catch null else null;
                }
                // Unknown fields are ignored per spec.
            }

            if (p.data_buf.items.len == 0) continue; // nothing to dispatch

            var data = p.data_buf.items;
            if (data[data.len - 1] == '\n') data = data[0 .. data.len - 1];
            return .{
                .event = if (p.event_buf.items.len != 0) p.event_buf.items else null,
                .id = if (p.id_buf.items.len != 0) p.id_buf.items else null,
                .data = data,
                .retry = retry,
            };
        }
    }
};

// ── tests (offline, canned byte sequences) ──────────────────────────────────

const testing = std.testing;

test "Parser: dispatches one event per blank line, joins multi-line data, skips comments" {
    const wire = "event: message_start\r\n" ++
        "data: {\"type\":\"message_start\"}\r\n" ++
        "\r\n" ++
        "event: content_block_delta\n" ++
        "data: line one\n" ++
        "data: line two\n" ++
        "data: line three\n" ++
        "\n" ++
        ": this is a heartbeat comment, ignored\n" ++
        "\n" ++
        "id: evt-9\n" ++
        "data: last\n" ++
        "\n";
    var reader: std.Io.Reader = .fixed(wire);
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();

    const e1 = (try p.next()).?;
    try testing.expectEqualStrings("message_start", e1.event.?);
    try testing.expectEqualStrings("{\"type\":\"message_start\"}", e1.data);
    try testing.expect(e1.id == null);
    try testing.expect(e1.retry == null);

    const e2 = (try p.next()).?;
    try testing.expectEqualStrings("content_block_delta", e2.event.?);
    try testing.expectEqualStrings("line one\nline two\nline three", e2.data);

    // The comment-only group between e2 and e3 produced no dispatch.
    const e3 = (try p.next()).?;
    try testing.expect(e3.event == null);
    try testing.expectEqualStrings("evt-9", e3.id.?);
    try testing.expectEqualStrings("last", e3.data);

    try testing.expect((try p.next()) == null);
}

test "Parser: retry field, id without colon-space, field with no colon" {
    const wire = "retry: 3000\n" ++
        "id:no-space-id\n" ++
        "data:x\n" ++
        "justafieldname\n" ++ // no colon at all -> field name only, empty value
        "\n";
    var reader: std.Io.Reader = .fixed(wire);
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();

    const e = (try p.next()).?;
    try testing.expectEqual(@as(u32, 3000), e.retry.?);
    try testing.expectEqualStrings("no-space-id", e.id.?);
    try testing.expectEqualStrings("x", e.data);
    try testing.expect((try p.next()) == null);
}

test "Parser: malformed retry is ignored, not fatal" {
    var reader: std.Io.Reader = .fixed("retry: not-a-number\ndata: ok\n\n");
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    const e = (try p.next()).?;
    try testing.expect(e.retry == null);
    try testing.expectEqualStrings("ok", e.data);
}

test "Parser: a group whose joined data exceeds max_data_bytes is DataTooLarge, and the buffer is released (A1 F3)" {
    // 300 legal 40-byte `data:` lines in ONE group: each line is well under
    // any per-line bound, the group is not.
    const line = "data: 0123456789012345678901234567890123\n";
    const wire = line ** 300 ++ "\n";
    var reader: std.Io.Reader = .fixed(wire);
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    p.max_data_bytes = 4096;
    try testing.expectError(error.DataTooLarge, p.next());
    try testing.expectEqual(@as(usize, 0), p.data_buf.capacity);
    // Exactly at the cap is fine: 100 lines × (34 + 1) = 3500 ≤ 4096.
    var reader2: std.Io.Reader = .fixed(line ** 100 ++ "\n");
    var p2 = Parser.init(&reader2, testing.allocator);
    defer p2.deinit();
    p2.max_data_bytes = 3500;
    const e = (try p2.next()).?;
    try testing.expectEqual(@as(usize, 3499), e.data.len);
    p2.max_data_bytes = 3499;
    var reader3: std.Io.Reader = .fixed(line ** 100 ++ "\n");
    p2.reader = &reader3;
    try testing.expectError(error.DataTooLarge, p2.next());
}

test "Parser: stream cut mid-group surfaces error.EndOfStream" {
    var reader: std.Io.Reader = .fixed("event: message_start\ndata: partial");
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    try testing.expectError(error.EndOfStream, p.next());
}

test "Parser: clean close between groups returns null" {
    var reader: std.Io.Reader = .fixed("data: one\n\n");
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    const e = (try p.next()).?;
    try testing.expectEqualStrings("one", e.data);
    try testing.expect((try p.next()) == null);
}

// ── regression: mutation-ladder gaps from A1 (F16, F17, F21, F24) ──────────

test "Parser: only ONE leading space is stripped from a field value, not every leading space (A1 F16)" {
    // Per spec: if the byte after the colon is U+0020 SPACE, remove it —
    // exactly one, not a trim of the whole run. `M16` (strip-all) and today's
    // code both pass on a single leading space; this is the case that tells
    // them apart.
    var reader: std.Io.Reader = .fixed("data:  two leading spaces\n\n");
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    const e = (try p.next()).?;
    try testing.expectEqualStrings(" two leading spaces", e.data);
}

test "Parser: an id: line with an embedded NUL is dropped, not just truncated (A1 F17)" {
    // Spec: a `\0` anywhere in the value invalidates the whole `id:` line —
    // the group dispatches with no id, not a truncated one.
    var reader: std.Io.Reader = .fixed("id: good\ndata: a\n\nid: bad\x00id\ndata: b\n\n");
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    const e1 = (try p.next()).?;
    try testing.expectEqualStrings("good", e1.id.?);
    const e2 = (try p.next()).?;
    try testing.expect(e2.id == null);
}

test "Parser: a second event: line in one group replaces the first, it does not accumulate (A1 F21)" {
    // `event_buf`/`id_buf` are `clearRetainingCapacity`d before each
    // append, so a repeated field is last-wins, not concatenated — but
    // nothing exercised a group with two `event:` lines before this.
    var reader: std.Io.Reader = .fixed("event: first\nevent: second\ndata: x\n\n");
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    const e = (try p.next()).?;
    try testing.expectEqualStrings("second", e.event.?);
}

test "Parser: retry: with a leading + is ignored, not parsed as a signed-looking int (A1 F24)" {
    // WHATWG: the value must consist of only ASCII digits; `std.fmt.parseInt`
    // alone accepts a leading `+`/`-`, which is laxer than spec.
    var reader: std.Io.Reader = .fixed("retry: +3000\ndata: a\n\n");
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    const e = (try p.next()).?;
    try testing.expect(e.retry == null);
}

test "Parser: a trailing CR that is part of the value survives, only the line terminator is stripped (A1 F24)" {
    // `takeDelimiterInclusive('\n')` only recognizes `\n`, so a value ending
    // in a literal `\r` followed by the real `\r\n` terminator is one raw
    // line, not two: `trimEnd(raw_line, "\r\n")` used to strip both,
    // swallowing a byte that belonged to the value.
    var reader: std.Io.Reader = .fixed("data: foo\r\r\n\n");
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    const e = (try p.next()).?;
    try testing.expectEqualStrings("foo\r", e.data);
}

test "Parser: a leading UTF-8 BOM on the stream's first line is skipped (A1 F24)" {
    var reader: std.Io.Reader = .fixed("\xEF\xBB\xBFevent: message_start\ndata: a\n\n");
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    const e = (try p.next()).?;
    try testing.expectEqualStrings("message_start", e.event.?);
    try testing.expectEqualStrings("a", e.data);
}

// A `LineTooLong` (`error.StreamTooLong` from the reader) needs a streaming
// reader whose internal buffer is smaller than the line but that still has
// more bytes behind it — `.fixed` can't reproduce that (its "buffer" is the
// whole slice, so an overlong line there is just `EndOfStream`). That case
// (A1 F14: does it surface as a real error or get degraded to a silent `null`
// end-of-stream?) is exercised end-to-end against a real loopback peer in
// `Client.zig`'s test of the same name.

// ── fuzz: untrusted SSE bytes never panic ───────────────────────────────────

fn fuzzParserNext(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf); // not `bytes` + a ranged length: that always yields 0
    var reader: std.Io.Reader = .fixed(buf[0..len]);
    var p = Parser.init(&reader, testing.allocator);
    defer p.deinit();
    while (true) {
        const ev = p.next() catch break;
        if (ev == null) break;
    }
}
test "fuzz Parser.next never panics" {
    try testing.fuzz({}, fuzzParserNext, .{ .corpus = &.{
        "event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
        "data: a\ndata: b\r\nid: x\x00y\nretry: 12\n\n: comment\n\ndata: partial",
    } });
}
