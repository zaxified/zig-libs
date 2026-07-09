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

/// A reusable field accumulator over one live `std.Io.Reader`. Does not
/// own the reader.
pub const Parser = struct {
    reader: *std.Io.Reader,
    gpa: std.mem.Allocator,
    event_buf: std.ArrayList(u8),
    id_buf: std.ArrayList(u8),
    data_buf: std.ArrayList(u8),

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
                const line = std.mem.trimEnd(u8, raw_line, "\r\n");
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
                    retry = std.fmt.parseInt(u32, val, 10) catch null;
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
