// SPDX-License-Identifier: MIT

//! RFC 6242 — the NETCONF-over-SSH framing protocol, both dialects.
//!
//! This file is pure state machine: bytes in, complete messages out. It owns
//! no socket, no thread and no timer, so it can be driven from an SSH channel,
//! a TCP stream, a test pipe or a fuzzer with identical results.
//!
//! Two framings exist and a session uses exactly one at a time:
//!
//! * `.end_of_message` (§4.3) — every message is terminated by the literal
//!   `]]>]]>`. Used for the `<hello>` exchange, and for the whole session when
//!   the peers do not both advertise `:base:1.1`.
//! * `.chunked` (§4.2) — `LF '#' chunk-size LF chunk-data` repeated, closed by
//!   `LF '#' '#' LF`. Mandatory once both peers advertise
//!   `urn:ietf:params:netconf:base:1.1`.
//!
//! The dialect switch happens at exactly one point — immediately after the
//! hello exchange — and `Framer.setDialect` refuses to move while a message is
//! half-decoded, so the transition can never be applied mid-frame.

const std = @import("std");
const testing = std.testing;

/// The end-of-message delimiter of RFC 6242 §4.3.
pub const eom_delimiter = "]]>]]>";

/// Which framing a session is currently using. See the file comment.
pub const Dialect = enum { end_of_message, chunked };

/// Resource ceilings. Every one of these is a hostile-input guard, not a
/// tuning knob: a peer that can make us buffer without bound is a DoS.
pub const Limits = struct {
    /// Largest decoded message we will assemble. RFC 6242 sets no ceiling, so
    /// one has to be chosen; 16 MiB comfortably holds a full `<get>` of a
    /// large device configuration.
    max_message: usize = 16 * 1024 * 1024,
    /// Largest single chunk we accept in `.chunked` framing. RFC 6242 §4.2
    /// caps chunk-size at 4294967295; anything above `max_chunk` is refused
    /// before a single byte is buffered.
    max_chunk: u64 = 4 * 1024 * 1024,
    /// Largest amount of not-yet-consumed input we hold. Bounds the damage of
    /// a peer that sends an endless message with no terminator in
    /// `.end_of_message` framing.
    max_pending: usize = 32 * 1024 * 1024,
};

/// The absolute chunk-size ceiling of RFC 6242 §4.2 ("the maximum allowed
/// chunk-size value is 4294967295").
pub const max_chunk_size_rfc: u64 = 4294967295;

pub const FramerError = error{
    /// A `\n#…` header that is not `\n#<1*DIGIT>\n` or `\n##\n`.
    MalformedChunkHeader,
    /// chunk-size was 0, or had a leading zero (RFC 6242 §4.2:
    /// `chunk-size = 1*DIGIT1 0*DIGIT`, "leading zeros are prohibited").
    InvalidChunkSize,
    /// chunk-size exceeded 4294967295 or the configured `max_chunk`.
    ChunkTooLarge,
    /// The assembled message exceeded `max_message`.
    MessageTooLarge,
    /// Un-terminated input exceeded `max_pending`.
    PendingTooLarge,
    /// `\n##\n` arrived with no preceding chunk (`Chunked-Message = 1*chunk
    /// end-of-chunks` requires at least one).
    EmptyChunkedMessage,
    /// In `.chunked` framing, the stream did not start at a chunk header.
    ExpectedChunkHeader,
} || std.mem.Allocator.Error;

pub const WriteError = error{
    /// The payload contains `]]>]]>`, so it cannot be framed with the
    /// end-of-message mechanism without the peer splitting the message at the
    /// wrong place. RFC 6242 §4.1 is explicit that the sequence *can* legally
    /// occur inside XML — refusing to send is the only safe answer.
    DelimiterInPayload,
    /// A chunk-size above what RFC 6242 permits was requested.
    ChunkTooLarge,
};

/// Incremental decoder. Feed it whatever bytes arrived (one byte, one packet,
/// one megabyte — identical results), then drain complete messages with
/// `next`. Nothing here reads or blocks.
///
///     var f: Framer = .init(gpa, .end_of_message, .{});
///     defer f.deinit();
///     try f.feed(bytes_from_the_wire);
///     while (try f.next()) |msg| { ... }   // msg is valid until the next call
pub const Framer = struct {
    gpa: std.mem.Allocator,
    dialect: Dialect,
    limits: Limits,

    /// Bytes received but not yet turned into a message.
    pending: std.ArrayList(u8) = .empty,
    /// How much of `pending` has already been folded into `msg`.
    cursor: usize = 0,
    /// The message currently being assembled (decoded payload, framing
    /// stripped).
    msg: std.ArrayList(u8) = .empty,
    /// True once any byte of the current message has been seen — the guard
    /// that makes the dialect switch safe.
    in_message: bool = false,
    /// `.chunked` only: bytes still to read for the chunk in progress.
    chunk_left: u64 = 0,
    /// `.chunked` only: whether at least one chunk was decoded for this
    /// message (the `1*chunk` of the ABNF).
    got_chunk: bool = false,
    /// The buffer holding the message handed to the caller. Kept separate from
    /// `msg` so that assembling message N+1 cannot invalidate message N until
    /// the caller asks for it.
    msg_out: std.ArrayList(u8) = .empty,
    /// Diagnostic: total bytes moved by `compact` over this framer's life.
    ///
    /// This is not a tuning knob and nothing in the decoder reads it. It exists
    /// because the *amortised* cost of compaction is a correctness property
    /// here — the peer chooses the chunk sizes, so a compaction per chunk is
    /// O(n²) in the chunk count — and an amortisation bound cannot be asserted
    /// with a stopwatch. The test named "compaction cost is linear in the wire
    /// size, not in the chunk count" is its only reader.
    compacted_bytes: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, dialect: Dialect, limits: Limits) Framer {
        return .{ .gpa = gpa, .dialect = dialect, .limits = limits };
    }

    pub fn deinit(self: *Framer) void {
        self.pending.deinit(self.gpa);
        self.msg.deinit(self.gpa);
        self.msg_out.deinit(self.gpa);
        self.* = undefined;
    }

    /// Switch framing. Only legal at a message boundary: after the hello
    /// exchange the very next byte belongs to the new dialect, and a decoder
    /// that let the dialect move mid-frame would mis-split the stream.
    pub fn setDialect(self: *Framer, d: Dialect) error{MidMessage}!void {
        if (self.in_message or self.msg.items.len != 0) return error.MidMessage;
        self.dialect = d;
        self.chunk_left = 0;
        self.got_chunk = false;
    }

    /// True when no message is half-decoded (nothing buffered at all).
    pub fn atBoundary(self: *const Framer) bool {
        return !self.in_message and self.msg.items.len == 0 and self.pending.items.len == self.cursor;
    }

    /// Push received bytes in. Does no decoding — `next` does that — so a
    /// caller may feed several reads before draining.
    pub fn feed(self: *Framer, bytes: []const u8) FramerError!void {
        self.compact();
        if (self.pending.items.len + bytes.len > self.limits.max_pending) return error.PendingTooLarge;
        try self.pending.appendSlice(self.gpa, bytes);
    }

    /// Decode the next complete message, or null if more bytes are needed.
    /// The returned slice is owned by the framer and stays valid until the
    /// next `next` call; copy it if you need to keep it.
    pub fn next(self: *Framer) FramerError!?[]const u8 {
        return switch (self.dialect) {
            .end_of_message => self.nextEom(),
            .chunked => self.nextChunked(),
        };
    }

    /// Drop the consumed prefix of `pending` so a long-lived session does not
    /// grow without bound. O(bytes still unconsumed) — see `maybeCompact` for
    /// why that makes the call site matter.
    fn compact(self: *Framer) void {
        if (self.cursor == 0) return;
        const rest = self.pending.items.len - self.cursor;
        self.compacted_bytes += rest;
        std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[self.cursor..]);
        self.pending.shrinkRetainingCapacity(rest);
        self.cursor = 0;
    }

    /// Compact only once the consumed prefix is at least half of `pending` —
    /// the standard amortisation rule.
    ///
    /// The decode loops MUST use this and not `compact`. A chunked message is
    /// `1*chunk`, the peer picks every chunk-size, and a compaction per chunk
    /// header plus one per chunk body moves the whole remaining buffer O(n)
    /// times: 655 KB of one-byte chunks cost 159 CPU-seconds before this rule
    /// existed. Under the rule each compaction copies at most half the buffer
    /// and discards at least the other half, so the copying is charged to bytes
    /// that are then gone for good and the total stays O(bytes fed).
    ///
    /// `feed` still compacts unconditionally: it is called once per read, and
    /// the `max_pending` ceiling must be measured against live bytes only.
    fn maybeCompact(self: *Framer) void {
        if (self.cursor == 0) return;
        if (self.cursor * 2 < self.pending.items.len) return;
        self.compact();
    }

    fn finish(self: *Framer) FramerError!?[]const u8 {
        self.in_message = false;
        self.got_chunk = false;
        // Hand out `msg` and reset it for the next message. `msg` keeps its
        // capacity across messages; the caller must copy before the next call.
        self.msg_out.clearRetainingCapacity();
        std.mem.swap(std.ArrayList(u8), &self.msg, &self.msg_out);
        return self.msg_out.items;
    }

    // ── §4.3 end-of-message ────────────────────────────────────────────────

    fn nextEom(self: *Framer) FramerError!?[]const u8 {
        const buf = self.pending.items[self.cursor..];
        if (buf.len != 0) self.in_message = true;
        if (std.mem.indexOf(u8, buf, eom_delimiter)) |idx| {
            if (self.msg.items.len + idx > self.limits.max_message) return error.MessageTooLarge;
            try self.msg.appendSlice(self.gpa, buf[0..idx]);
            self.cursor += idx + eom_delimiter.len;
            self.maybeCompact();
            return self.finish();
        }
        // No delimiter yet. Absorb everything except a possible partial
        // delimiter at the tail (a delimiter split across two reads must still
        // be recognised).
        const keep = @min(buf.len, eom_delimiter.len - 1);
        const take = buf.len - keep;
        if (take > 0) {
            if (self.msg.items.len + take > self.limits.max_message) return error.MessageTooLarge;
            try self.msg.appendSlice(self.gpa, buf[0..take]);
            self.cursor += take;
            self.maybeCompact();
        }
        return null;
    }

    // ── §4.2 chunked ───────────────────────────────────────────────────────

    fn nextChunked(self: *Framer) FramerError!?[]const u8 {
        while (true) {
            if (self.chunk_left > 0) {
                const buf = self.pending.items[self.cursor..];
                if (buf.len == 0) return null;
                const take = @min(@as(u64, buf.len), self.chunk_left);
                const n: usize = @intCast(take);
                if (self.msg.items.len + n > self.limits.max_message) return error.MessageTooLarge;
                try self.msg.appendSlice(self.gpa, buf[0..n]);
                self.cursor += n;
                self.chunk_left -= take;
                self.maybeCompact();
                continue;
            }

            // At a header boundary: `\n#<size>\n` or `\n##\n`.
            var buf = self.pending.items[self.cursor..];
            // Interop tolerance, and only here: a peer that terminated its
            // `<hello>` with `]]>]]>\n` (the RFC's examples print the
            // delimiter on its own line) leaves a stray LF in front of the
            // first chunk header. Skipping LFs that are *followed by another
            // LF* can never consume the LF that starts a real header, and each
            // skipped byte is consumed, so it is not an unbounded input.
            while (!self.in_message and self.got_chunk == false and
                buf.len >= 2 and buf[0] == '\n' and buf[1] == '\n')
            {
                self.cursor += 1;
                self.maybeCompact();
                buf = self.pending.items[self.cursor..];
            }
            if (buf.len < 2) return null; // need at least "\n#"
            if (buf[0] != '\n' or buf[1] != '#') return error.ExpectedChunkHeader;
            self.in_message = true;

            if (buf.len < 3) return null;
            if (buf[2] == '#') {
                if (buf.len < 4) return null;
                if (buf[3] != '\n') return error.MalformedChunkHeader;
                if (!self.got_chunk) return error.EmptyChunkedMessage;
                self.cursor += 4;
                self.maybeCompact();
                return self.finish();
            }

            // chunk-size = 1*DIGIT1 0*DIGIT — no leading zero, max 10 digits.
            var i: usize = 2;
            var size: u64 = 0;
            while (i < buf.len and buf[i] != '\n') : (i += 1) {
                const c = buf[i];
                if (c < '0' or c > '9') return error.MalformedChunkHeader;
                if (i == 2 and c == '0') return error.InvalidChunkSize; // leading zero
                if (i - 2 >= 10) return error.ChunkTooLarge; // >10 digits cannot be <= 4294967295
                size = size * 10 + (c - '0');
            }
            if (i == buf.len) {
                // Header not complete yet. Bound the wait: a header longer
                // than "\n#" + 10 digits + "\n" is malformed by construction.
                if (buf.len > 13) return error.MalformedChunkHeader;
                return null;
            }
            if (i == 2) return error.MalformedChunkHeader; // "\n#\n" — no digits
            if (size == 0) return error.InvalidChunkSize;
            if (size > max_chunk_size_rfc or size > self.limits.max_chunk) return error.ChunkTooLarge;

            self.cursor += i + 1; // past the LF that ends the header
            self.maybeCompact();
            self.chunk_left = size;
            self.got_chunk = true;
        }
    }
};

// ── encoder ────────────────────────────────────────────────────────────────

/// Frame one message into `w`.
///
/// `.end_of_message`: `payload` then `]]>]]>`; a payload that itself contains
/// `]]>]]>` is refused (see `WriteError.DelimiterInPayload`).
/// `.chunked`: a single chunk of `payload.len` bytes plus `\n##\n`. Use
/// `writeChunked` to split a large payload across several chunks.
pub fn writeMessage(w: *std.Io.Writer, dialect: Dialect, payload: []const u8) (WriteError || std.Io.Writer.Error)!void {
    switch (dialect) {
        .end_of_message => {
            if (std.mem.indexOf(u8, payload, eom_delimiter) != null) return error.DelimiterInPayload;
            try w.writeAll(payload);
            // The RFC's examples put `]]>]]>` on a line of its own, so a LF is
            // added when the payload does not already end with one. Nothing is
            // written AFTER the delimiter: a trailing LF would be the first
            // byte of the next message, and in chunked framing the next
            // message must begin exactly at its `\n#` header.
            if (payload.len != 0 and payload[payload.len - 1] != '\n') try w.writeByte('\n');
            try w.writeAll(eom_delimiter);
        },
        .chunked => try writeChunked(w, payload, payload.len),
    }
}

/// Chunked framing with an explicit maximum chunk size — the shape a sender
/// with a bounded output buffer wants. `chunk_size` 0 means "one chunk".
pub fn writeChunked(w: *std.Io.Writer, payload: []const u8, chunk_size: usize) (WriteError || std.Io.Writer.Error)!void {
    if (payload.len == 0) return error.ChunkTooLarge; // chunk-data = 1*OCTET
    const step = if (chunk_size == 0) payload.len else chunk_size;
    if (step > max_chunk_size_rfc) return error.ChunkTooLarge;
    var off: usize = 0;
    while (off < payload.len) {
        const n = @min(step, payload.len - off);
        try w.print("\n#{d}\n", .{n});
        try w.writeAll(payload[off .. off + n]);
        off += n;
    }
    try w.writeAll("\n##\n");
}

/// Frame into a freshly allocated buffer (the ergonomic form for tests and
/// for callers that hand whole buffers to a transport).
pub fn frameAlloc(
    gpa: std.mem.Allocator,
    dialect: Dialect,
    payload: []const u8,
) (WriteError || std.mem.Allocator.Error)![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    writeMessage(&aw.writer, dialect, payload) catch |e| switch (e) {
        error.WriteFailed => return error.OutOfMemory,
        else => |other| return other,
    };
    return aw.toOwnedSlice();
}

// ── tests ──────────────────────────────────────────────────────────────────

/// Feed `input` one byte at a time and collect every message. A framer that
/// only works on whole-datagram reads is broken; every decode test below runs
/// through this as well as through a single feed.
fn collectByteAtATime(gpa: std.mem.Allocator, dialect: Dialect, input: []const u8) !std.ArrayList([]u8) {
    var f: Framer = .init(gpa, dialect, .{});
    defer f.deinit();
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |m| gpa.free(m);
        out.deinit(gpa);
    }
    for (input) |b| {
        try f.feed(&[_]u8{b});
        while (try f.next()) |m| try out.append(gpa, try gpa.dupe(u8, m));
    }
    return out;
}

fn collectWhole(gpa: std.mem.Allocator, dialect: Dialect, input: []const u8) !std.ArrayList([]u8) {
    var f: Framer = .init(gpa, dialect, .{});
    defer f.deinit();
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |m| gpa.free(m);
        out.deinit(gpa);
    }
    try f.feed(input);
    while (try f.next()) |m| try out.append(gpa, try gpa.dupe(u8, m));
    return out;
}

fn freeAll(gpa: std.mem.Allocator, list: *std.ArrayList([]u8)) void {
    for (list.items) |m| gpa.free(m);
    list.deinit(gpa);
}

test "eom: single message, whole read and byte-at-a-time agree" {
    const gpa = testing.allocator;
    const wire = "<hello/>]]>]]>";
    var a = try collectWhole(gpa, .end_of_message, wire);
    defer freeAll(gpa, &a);
    var b = try collectByteAtATime(gpa, .end_of_message, wire);
    defer freeAll(gpa, &b);
    try testing.expectEqual(@as(usize, 1), a.items.len);
    try testing.expectEqual(@as(usize, 1), b.items.len);
    try testing.expectEqualStrings("<hello/>", a.items[0]);
    try testing.expectEqualStrings("<hello/>", b.items[0]);
}

test "eom: RFC 6242 §4.3 literal exchange decodes to the two documents" {
    // Byte-exact from RFC 6242 §4.3 (the "C:"/"S:" prefixes are the RFC's
    // presentation, not wire bytes).
    const gpa = testing.allocator;
    const client =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<rpc message-id=\"105\"\n" ++
        "xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n" ++
        "  <get-config>\n" ++
        "    <source><running/></source>\n" ++
        "    <config xmlns=\"http://example.com/schema/1.2/config\">\n" ++
        "     <users/>\n" ++
        "    </config>\n" ++
        "  </get-config>\n" ++
        "</rpc>\n";
    const server =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<rpc-reply message-id=\"105\"\n" ++
        "xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n" ++
        "  <config xmlns=\"http://example.com/schema/1.2/config\">\n" ++
        "    <users>\n" ++
        "      <user><name>root</name><type>superuser</type></user>\n" ++
        "      <user><name>fred</name><type>admin</type></user>\n" ++
        "      <user><name>barney</name><type>admin</type></user>\n" ++
        "    </users>\n" ++
        "  </config>\n" ++
        "</rpc-reply>\n";
    const wire = client ++ "]]>]]>\n" ++ server ++ "]]>]]>\n";

    var msgs = try collectByteAtATime(gpa, .end_of_message, wire);
    defer freeAll(gpa, &msgs);
    try testing.expectEqual(@as(usize, 2), msgs.items.len);
    try testing.expectEqualStrings(client, msgs.items[0]);
    // The LF after the first delimiter belongs to the next message's prolog.
    try testing.expectEqualStrings("\n" ++ server, msgs.items[1]);
}

test "eom: delimiter split across reads is still recognised" {
    const gpa = testing.allocator;
    var f: Framer = .init(gpa, .end_of_message, .{});
    defer f.deinit();
    try f.feed("<a/>]]");
    try testing.expect((try f.next()) == null);
    try f.feed(">");
    try testing.expect((try f.next()) == null);
    try f.feed("]]>rest");
    const m = (try f.next()).?;
    try testing.expectEqualStrings("<a/>", m);
    try testing.expect((try f.next()) == null);
}

test "chunked: RFC 6242 §4.2 literal example decodes byte-exactly" {
    // RFC 6242 §4.2: the message
    //   <rpc message-id="102"
    //        xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    //     <close-session/>
    //   </rpc>
    // encoded as chunks of 4, 18 and 79 octets. Reproduced verbatim.
    const gpa = testing.allocator;
    const wire =
        "\n#4\n" ++
        "<rpc" ++
        "\n#18\n" ++
        " message-id=\"102\"\n" ++
        "\n#79\n" ++
        "     xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n" ++
        "  <close-session/>\n" ++
        "</rpc>" ++
        "\n##\n";
    const want =
        "<rpc message-id=\"102\"\n" ++
        "     xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n" ++
        "  <close-session/>\n" ++
        "</rpc>";

    var a = try collectWhole(gpa, .chunked, wire);
    defer freeAll(gpa, &a);
    try testing.expectEqual(@as(usize, 1), a.items.len);
    try testing.expectEqualStrings(want, a.items[0]);

    var b = try collectByteAtATime(gpa, .chunked, wire);
    defer freeAll(gpa, &b);
    try testing.expectEqual(@as(usize, 1), b.items.len);
    try testing.expectEqualStrings(want, b.items[0]);
}

test "chunked: the RFC's own chunk sizes are what the ABNF says they are" {
    // Guards the golden above against a typo: 4 + 18 + 79 must be the exact
    // lengths of the three literal pieces.
    try testing.expectEqual(@as(usize, 4), "<rpc".len);
    try testing.expectEqual(@as(usize, 18), " message-id=\"102\"\n".len);
    try testing.expectEqual(@as(usize, 79), ("     xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n" ++
        "  <close-session/>\n" ++ "</rpc>").len);
}

test "chunked: ]]>]]> inside chunk data is data, not a delimiter" {
    const gpa = testing.allocator;
    const payload = "<rpc><x>a]]>]]>b</x></rpc>";
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeChunked(&w, payload, 0);
    var msgs = try collectByteAtATime(gpa, .chunked, w.buffered());
    defer freeAll(gpa, &msgs);
    try testing.expectEqual(@as(usize, 1), msgs.items.len);
    try testing.expectEqualStrings(payload, msgs.items[0]);
}

test "chunked: multi-chunk and multi-message streams" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try writeChunked(&aw.writer, "<a>0123456789</a>", 3);
    try writeChunked(&aw.writer, "<b/>", 0);
    var msgs = try collectByteAtATime(gpa, .chunked, aw.written());
    defer freeAll(gpa, &msgs);
    try testing.expectEqual(@as(usize, 2), msgs.items.len);
    try testing.expectEqualStrings("<a>0123456789</a>", msgs.items[0]);
    try testing.expectEqualStrings("<b/>", msgs.items[1]);
}

test "chunked: compaction cost is linear in the wire size, not in the chunk count" {
    const gpa = testing.allocator;
    const n = 4096;

    // The peer picks the chunk sizes, and one byte per chunk is legal
    // (`chunk-size = 1*DIGIT1 0*DIGIT`, minimum 1). Compacting `pending` per
    // chunk made this quadratic: 655 KB of such wire cost 159 CPU-seconds.
    //
    // The oracle is `compacted_bytes`, not a stopwatch: the amortisation rule
    // says every byte copied out of `pending` is paid for by a byte discarded
    // from it, so the lifetime total cannot exceed the bytes fed in. A
    // per-chunk compaction blows through this by ~n/10.
    {
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        for (0..n) |_| try wire.appendSlice(gpa, "\n#1\nX");
        try wire.appendSlice(gpa, "\n##\n");

        var f: Framer = .init(gpa, .chunked, .{});
        defer f.deinit();
        try f.feed(wire.items);
        const msg = (try f.next()).?;
        try testing.expectEqual(@as(usize, n), msg.len);
        try testing.expect(f.compacted_bytes <= 2 * wire.items.len);
    }

    // The same bound across many *messages* drained from a single feed. This
    // is the case a "compact once per next() instead of per chunk" fix would
    // still get wrong, because next() is called once per message.
    {
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        for (0..n) |_| try wire.appendSlice(gpa, "\n#1\nX\n##\n");

        var f: Framer = .init(gpa, .chunked, .{});
        defer f.deinit();
        try f.feed(wire.items);
        var count: usize = 0;
        while (try f.next()) |m| : (count += 1) try testing.expectEqualStrings("X", m);
        try testing.expectEqual(@as(usize, n), count);
        try testing.expect(f.compacted_bytes <= 2 * wire.items.len);
    }
}

test "chunked hostile: malformed headers are typed errors, never accepted" {
    const gpa = testing.allocator;
    const cases = [_]struct { wire: []const u8, want: anyerror }{
        .{ .wire = "\n#0\n\n##\n", .want = error.InvalidChunkSize }, // zero size
        .{ .wire = "\n#04\nabcd\n##\n", .want = error.InvalidChunkSize }, // leading zero
        .{ .wire = "\n#\n", .want = error.MalformedChunkHeader }, // no digits
        .{ .wire = "\n#4x\n", .want = error.MalformedChunkHeader }, // non-digit
        .{ .wire = "\n#4 \n", .want = error.MalformedChunkHeader }, // space
        .{ .wire = "\n#-4\n", .want = error.MalformedChunkHeader }, // negative
        .{ .wire = "\n##x", .want = error.MalformedChunkHeader }, // bad end-of-chunks
        .{ .wire = "\n##\n", .want = error.EmptyChunkedMessage }, // 1*chunk violated
        .{ .wire = "\n#99999999999\n", .want = error.ChunkTooLarge }, // 11 digits
        .{ .wire = "\n#4294967296\nx", .want = error.ChunkTooLarge }, // over the RFC cap
        .{ .wire = "<rpc/>]]>]]>", .want = error.ExpectedChunkHeader }, // eom framing offered
        .{ .wire = "#4\nabcd", .want = error.ExpectedChunkHeader }, // missing LF
        .{ .wire = "\n#123456789012345\n", .want = error.ChunkTooLarge }, // 15 digits
        .{ .wire = "\n#1234567890123456789012", .want = error.ChunkTooLarge }, // never-ending header
    };
    for (cases) |c| {
        // Whole-read...
        {
            var f: Framer = .init(gpa, .chunked, .{});
            defer f.deinit();
            try f.feed(c.wire);
            try testing.expectError(c.want, f.next());
        }
        // ...and byte-at-a-time must agree on the verdict.
        {
            var f: Framer = .init(gpa, .chunked, .{});
            defer f.deinit();
            var got: anyerror!?[]const u8 = null;
            for (c.wire) |b| {
                try f.feed(&[_]u8{b});
                got = f.next();
                if (got) |_| {} else |_| break;
            }
            try testing.expectError(c.want, got);
        }
    }
}

test "chunked: a chunk larger than the configured limit is refused before buffering" {
    const gpa = testing.allocator;
    var f: Framer = .init(gpa, .chunked, .{ .max_chunk = 8 });
    defer f.deinit();
    try f.feed("\n#9\n");
    try testing.expectError(error.ChunkTooLarge, f.next());
}

test "message and pending ceilings are enforced" {
    const gpa = testing.allocator;
    {
        var f: Framer = .init(gpa, .end_of_message, .{ .max_message = 4 });
        defer f.deinit();
        try f.feed("abcdefghij");
        try testing.expectError(error.MessageTooLarge, f.next());
    }
    {
        var f: Framer = .init(gpa, .end_of_message, .{ .max_pending = 4 });
        defer f.deinit();
        try testing.expectError(error.PendingTooLarge, f.feed("abcdefghij"));
    }
}

test "dialect switch is only legal at a message boundary" {
    const gpa = testing.allocator;
    var f: Framer = .init(gpa, .end_of_message, .{});
    defer f.deinit();
    try f.feed("<hello/>");
    try testing.expect((try f.next()) == null);
    try testing.expectError(error.MidMessage, f.setDialect(.chunked));

    try f.feed("]]>]]>");
    const hello = (try f.next()).?;
    try testing.expectEqualStrings("<hello/>", hello);
    try testing.expect(f.atBoundary());
    try f.setDialect(.chunked);

    // From here on the stream is chunked, and the ]]>]]> that would have ended
    // a message a moment ago is now ordinary data.
    try f.feed("\n#11\n<rpc>]]>]]>\n##\n");
    const m = (try f.next()).?;
    try testing.expectEqualStrings("<rpc>]]>]]>", m);
}

test "chunked: a stray LF from a `]]>]]>\\n`-terminated hello is tolerated, not a header error" {
    // A peer that printed its <hello> delimiter on its own line (as RFC 6242's
    // examples do) leaves one extra LF in front of the first chunk header once
    // the session switches to .chunked. Without the tolerance this LF would
    // make the header parser see "\n\n#4\n..." and reject it as
    // ExpectedChunkHeader (ordinary bytes, not a header, at the front of the
    // stream); with it the stray LF is skipped and the message decodes
    // normally.
    const gpa = testing.allocator;

    // Whole-read.
    {
        var f: Framer = .init(gpa, .chunked, .{});
        defer f.deinit();
        try f.feed("\n\n#4\n<rpc\n##\n");
        const m = (try f.next()).?;
        try testing.expectEqualStrings("<rpc", m);
    }
    // Byte-at-a-time must agree.
    {
        var msgs = try collectByteAtATime(gpa, .chunked, "\n\n#4\n<rpc\n##\n");
        defer freeAll(gpa, &msgs);
        try testing.expectEqual(@as(usize, 1), msgs.items.len);
        try testing.expectEqualStrings("<rpc", msgs.items[0]);
    }
    // The tolerance only fires before any chunk of the message has been
    // decoded: a stray "\n\n" *between* chunks of the same message is
    // ordinary data flowing into the next chunk header check, not something
    // to be silently skipped, so it is rejected exactly like any other
    // malformed header.
    {
        var f: Framer = .init(gpa, .chunked, .{});
        defer f.deinit();
        try f.feed("\n#4\n<rpc" ++ "\n\n#5\n");
        try testing.expectError(error.ExpectedChunkHeader, f.next());
    }
}

test "writeMessage: eom refuses a payload containing the delimiter" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.DelimiterInPayload, writeMessage(&w, .end_of_message, "<a>]]>]]></a>"));
}

test "writeMessage round-trips through the framer in both dialects" {
    const gpa = testing.allocator;
    const payloads = [_][]const u8{ "<rpc/>", "<rpc><a>x</a></rpc>", "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>" };
    for ([_]Dialect{ .end_of_message, .chunked }) |d| {
        for (payloads) |p| {
            const framed = try frameAlloc(gpa, d, p);
            defer gpa.free(framed);
            var msgs = try collectByteAtATime(gpa, d, framed);
            defer freeAll(gpa, &msgs);
            try testing.expectEqual(@as(usize, 1), msgs.items.len);
            // eom framing adds the LF that puts `]]>]]>` on its own line; that
            // LF is part of the (whitespace-insignificant) document.
            const got = msgs.items[0];
            try testing.expect(std.mem.startsWith(u8, got, p));
            try testing.expect(got.len - p.len <= 1);
        }
    }
}

test "fuzz: no input can make the framer crash or leak" {
    try testing.fuzz({}, fuzzFramer, .{});
}

fn fuzzFramer(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const input = raw[0..len];
    for ([_]Dialect{ .end_of_message, .chunked }) |d| {
        var f: Framer = .init(gpa, d, .{ .max_message = 4096, .max_chunk = 4096, .max_pending = 8192 });
        defer f.deinit();
        f.feed(input) catch continue;
        while (true) {
            const m = f.next() catch break;
            if (m == null) break;
        }
    }
}
