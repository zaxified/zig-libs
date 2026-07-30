// SPDX-License-Identifier: MIT

//! Length-Prefixed-Message framing — the five bytes that turn an HTTP/2 DATA
//! stream into a sequence of gRPC messages:
//!
//! ```text
//! ┌────────────┬──────────────────────────┬─────────────────┐
//! │ compressed │  message length (u32 BE) │  message bytes  │
//! │  1 byte    │        4 bytes           │   `length`      │
//! └────────────┴──────────────────────────┴─────────────────┘
//! ```
//!
//! ## The whole point of this file
//!
//! **DATA-frame boundaries and message boundaries are unrelated.** One DATA
//! frame may carry three messages, or the first two bytes of one; the same
//! message routinely arrives split across several DATA frames because the
//! peer's HTTP/2 `SETTINGS_MAX_FRAME_SIZE` (16 KiB by default) is smaller
//! than the message. A deframer that assumes "one read = one message" works
//! perfectly against a toy peer and fails against every real one, so the
//! split is the *normal* case here, not an edge case.
//!
//! ## The security-critical part
//!
//! `length` is read from the wire. Sizing anything from it before checking
//! it is the classic remote-memory-exhaustion primitive: five bytes claiming
//! `0xFFFFFFFF` would ask for 4 GiB. This deframer therefore has an
//! invariant stronger than "validate before allocating":
//!
//! > **The declared length never sizes an allocation at all.**
//!
//! The only buffer that grows is the reassembly buffer, and it only ever
//! grows by bytes that *actually arrived*. The declared length is used for
//! exactly two things: to compare against `max_recv_message_size` (checked
//! the instant the 5-byte header is complete, before another byte is
//! accepted) and to decide whether enough bytes are present yet. So a lying
//! header costs the liar the bandwidth of every byte it claims, and costs us
//! nothing — and past the limit it costs even that, because the call fails
//! at the header.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Bytes of prefix before every message: 1 flag + 4 length.
pub const header_len = 5;

/// gRPC's own default receive limit, and therefore ours: 4 MiB.
pub const default_max_recv_message_size: u32 = 4 * 1024 * 1024;

pub const Error = error{
    /// A declared message length exceeds `max_recv_message_size`. Surfaced
    /// to callers as the gRPC status `RESOURCE_EXHAUSTED`, which is what
    /// other implementations return for the same condition.
    MessageTooLarge,
    /// The compressed flag is set but no message encoding was negotiated
    /// that this build can undo.
    CompressedUnsupported,
    /// The stream ended in the middle of a length-prefixed message.
    TruncatedMessage,
    OutOfMemory,
};

/// A parsed 5-byte prefix.
pub const Header = struct {
    compressed: bool,
    /// Declared payload length — **untrusted**; see the module doc.
    length: u32,
};

/// Write the 5-byte prefix for a message of `length` bytes.
pub fn writeHeader(out: *[header_len]u8, compressed: bool, length: u32) void {
    out[0] = @intFromBool(compressed);
    // Big-endian, per the spec. Getting this backwards is invisible to a
    // round trip against ourselves and fatal against anyone else.
    std.mem.writeInt(u32, out[1..header_len], length, .big);
}

/// Parse the 5-byte prefix. Cannot fail — every bit pattern is a
/// syntactically valid header; whether the length is *acceptable* is the
/// deframer's question, not this one's.
pub fn parseHeader(bytes: *const [header_len]u8) Header {
    return .{
        .compressed = bytes[0] != 0,
        .length = std.mem.readInt(u32, bytes[1..header_len], .big),
    };
}

/// Frame `message` into `out`, which must be `header_len + message.len`
/// bytes. No allocation.
pub fn encodeInto(out: []u8, message: []const u8) void {
    std.debug.assert(out.len == header_len + message.len);
    writeHeader(out[0..header_len], false, @intCast(message.len));
    @memcpy(out[header_len..], message);
}

/// Frame `message` into a fresh, exactly-sized buffer the caller owns.
pub fn encodeAlloc(gpa: Allocator, message: []const u8) Allocator.Error![]u8 {
    const buf = try gpa.alloc(u8, header_len + message.len);
    encodeInto(buf, message);
    return buf;
}

/// Reassembles length-prefixed messages out of an arbitrarily chopped byte
/// stream. Feed it whatever a read produced with `push`, then drain complete
/// messages with `next` until it returns null.
///
/// Lifetime: a slice returned by `next` points into the deframer's buffer
/// and stays valid **until the next `push`** (which may compact or reallocate
/// it). `next` alone never invalidates a previous result, so a drain loop
/// that consumes each message before reading more bytes is safe; hold one
/// across a `push` and it is not.
pub const Deframer = struct {
    buf: std.ArrayList(u8) = .empty,
    /// Start of the not-yet-parsed region of `buf`.
    pos: usize = 0,
    /// Hard ceiling on a single message, checked against the *declared*
    /// length the moment a header completes.
    max_recv_message_size: u32 = default_max_recv_message_size,
    /// Whether a set compressed flag can be handled. False for this build
    /// (identity only), so a compressed frame fails loudly instead of being
    /// handed to a decoder as if it were plain protobuf.
    accept_compressed: bool = false,

    pub fn deinit(d: *Deframer, gpa: Allocator) void {
        d.buf.deinit(gpa);
        d.* = undefined;
    }

    /// Accept `bytes` (any length, including a partial header) and validate
    /// as far as the bytes allow. Returns `MessageTooLarge` as soon as a
    /// completed header declares more than the limit — before the payload it
    /// promises has any chance to be buffered.
    pub fn push(d: *Deframer, gpa: Allocator, bytes: []const u8) Error!void {
        if (bytes.len == 0) return d.checkHead();
        // Compact first so a long stream of small messages does not grow the
        // buffer without bound behind the read cursor.
        if (d.pos != 0) {
            const rest = d.buf.items.len - d.pos;
            std.mem.copyForwards(u8, d.buf.items[0..rest], d.buf.items[d.pos..]);
            d.buf.shrinkRetainingCapacity(rest);
            d.pos = 0;
        }
        try d.buf.appendSlice(gpa, bytes);
        return d.checkHead();
    }

    /// The next complete message, or null when more bytes are needed.
    pub fn next(d: *Deframer) Error!?[]const u8 {
        const avail = d.buf.items[d.pos..];
        if (avail.len < header_len) return null;
        const h = parseHeader(avail[0..header_len]);
        // Re-checked here as well as in `push`: `next` must never hand back a
        // message that the limit forbids, no matter how the bytes arrived.
        if (h.length > d.max_recv_message_size) return error.MessageTooLarge;
        if (h.compressed and !d.accept_compressed) return error.CompressedUnsupported;
        if (avail.len - header_len < h.length) return null;
        d.pos += header_len + h.length;
        return avail[header_len .. header_len + h.length];
    }

    /// Bytes held for a message that is still incomplete. Non-zero when the
    /// stream ends is a truncated message (`endOfStream`).
    pub fn pending(d: *const Deframer) usize {
        return d.buf.items.len - d.pos;
    }

    /// Assert the stream ended on a message boundary. A stream that stops
    /// mid-message is a protocol error, not an empty read: silently dropping
    /// the partial bytes would turn a truncated response into a short one.
    pub fn endOfStream(d: *const Deframer) Error!void {
        if (d.pending() != 0) return error.TruncatedMessage;
    }

    /// Validate a header as soon as its five bytes are present, so an
    /// oversized declaration is refused at the header rather than after its
    /// payload has been buffered.
    fn checkHead(d: *Deframer) Error!void {
        const avail = d.buf.items[d.pos..];
        if (avail.len < header_len) return;
        const h = parseHeader(avail[0..header_len]);
        if (h.length > d.max_recv_message_size) return error.MessageTooLarge;
        if (h.compressed and !d.accept_compressed) return error.CompressedUnsupported;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "frame: header is 1 flag + 4 big-endian length" {
    var out: [header_len]u8 = undefined;
    writeHeader(&out, false, 0x01020304);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x02, 0x03, 0x04 }, &out);

    writeHeader(&out, true, 5);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x00, 0x00, 0x05 }, &out);

    const h = parseHeader(&.{ 0x00, 0x00, 0x00, 0x00, 0x05 });
    try testing.expect(!h.compressed);
    try testing.expectEqual(@as(u32, 5), h.length);
}

test "frame: encode produces exactly prefix + payload" {
    const gpa = testing.allocator;
    const bytes = try encodeAlloc(gpa, "hello");
    defer gpa.free(bytes);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o' }, bytes);

    const empty = try encodeAlloc(gpa, "");
    defer gpa.free(empty);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0 }, empty);
}

test "deframe: several messages inside one push" {
    const gpa = testing.allocator;
    var d: Deframer = .{};
    defer d.deinit(gpa);

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    for ([_][]const u8{ "a", "bb", "", "cccc" }) |m| {
        const f = try encodeAlloc(gpa, m);
        defer gpa.free(f);
        try wire.appendSlice(gpa, f);
    }

    try d.push(gpa, wire.items);
    try testing.expectEqualStrings("a", (try d.next()).?);
    try testing.expectEqualStrings("bb", (try d.next()).?);
    try testing.expectEqualStrings("", (try d.next()).?);
    try testing.expectEqualStrings("cccc", (try d.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try d.next());
    try d.endOfStream();
}

test "deframe: one message split across every possible boundary" {
    const gpa = testing.allocator;
    const payload = "the quick brown fox jumps over the lazy dog";
    const framed = try encodeAlloc(gpa, payload);
    defer gpa.free(framed);

    // Every single split point, including inside the 5-byte header — the
    // header itself arrives in pieces just as readily as the payload does.
    for (1..framed.len) |cut| {
        var d: Deframer = .{};
        defer d.deinit(gpa);
        try d.push(gpa, framed[0..cut]);
        try testing.expectEqual(@as(?[]const u8, null), try d.next());
        try d.push(gpa, framed[cut..]);
        try testing.expectEqualStrings(payload, (try d.next()).?);
        try testing.expectEqual(@as(?[]const u8, null), try d.next());
        try d.endOfStream();
    }
}

test "deframe: byte-at-a-time delivery of a multi-message stream" {
    const gpa = testing.allocator;
    var d: Deframer = .{};
    defer d.deinit(gpa);

    const msgs = [_][]const u8{ "one", "two", "three", "" };
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    for (msgs) |m| {
        const f = try encodeAlloc(gpa, m);
        defer gpa.free(f);
        try wire.appendSlice(gpa, f);
    }

    var got: usize = 0;
    for (wire.items) |b| {
        try d.push(gpa, &.{b});
        while (try d.next()) |m| {
            try testing.expectEqualStrings(msgs[got], m);
            got += 1;
        }
    }
    try testing.expectEqual(msgs.len, got);
    try d.endOfStream();
}

test "deframe: a message that stops short is truncated, not empty" {
    const gpa = testing.allocator;
    var d: Deframer = .{};
    defer d.deinit(gpa);
    const framed = try encodeAlloc(gpa, "abcdef");
    defer gpa.free(framed);

    try d.push(gpa, framed[0 .. framed.len - 1]);
    try testing.expectEqual(@as(?[]const u8, null), try d.next());
    try testing.expectError(error.TruncatedMessage, d.endOfStream());

    // Even a lone partial header counts.
    var d2: Deframer = .{};
    defer d2.deinit(gpa);
    try d2.push(gpa, &.{ 0, 0, 0 });
    try testing.expectError(error.TruncatedMessage, d2.endOfStream());
}

test "deframe: the declared length is refused at the header, before its payload" {
    const gpa = testing.allocator;
    var d: Deframer = .{ .max_recv_message_size = 16 };
    defer d.deinit(gpa);

    // Five bytes claiming 4 GiB. Nothing is allocated for it.
    try testing.expectError(error.MessageTooLarge, d.push(gpa, &.{ 0, 0xff, 0xff, 0xff, 0xff }));
    // The five bytes that arrived are all that was ever held: the declared
    // 4 GiB sized nothing.
    try testing.expectEqual(@as(usize, 5), d.buf.items.len);

    // One byte over the limit is over the limit.
    var d2: Deframer = .{ .max_recv_message_size = 16 };
    defer d2.deinit(gpa);
    try testing.expectError(error.MessageTooLarge, d2.push(gpa, &.{ 0, 0, 0, 0, 17 }));

    // Exactly at the limit is fine.
    var d3: Deframer = .{ .max_recv_message_size = 16 };
    defer d3.deinit(gpa);
    const at_limit = try encodeAlloc(gpa, "0123456789abcdef");
    defer gpa.free(at_limit);
    try d3.push(gpa, at_limit);
    try testing.expectEqualStrings("0123456789abcdef", (try d3.next()).?);
}

test "deframe: a header split across pushes is still checked once complete" {
    const gpa = testing.allocator;
    var d: Deframer = .{ .max_recv_message_size = 16 };
    defer d.deinit(gpa);
    try d.push(gpa, &.{ 0, 0xff, 0xff }); // incomplete: nothing to judge yet
    try testing.expectError(error.MessageTooLarge, d.push(gpa, &.{ 0xff, 0xff }));
}

test "deframe: a compressed frame is refused, not fed to the decoder" {
    const gpa = testing.allocator;
    var d: Deframer = .{};
    defer d.deinit(gpa);
    try testing.expectError(
        error.CompressedUnsupported,
        d.push(gpa, &.{ 1, 0, 0, 0, 3, 'x', 'y', 'z' }),
    );
}

test "deframe: the buffer does not grow with the number of messages consumed" {
    const gpa = testing.allocator;
    var d: Deframer = .{};
    defer d.deinit(gpa);
    const framed = try encodeAlloc(gpa, "0123456789");
    defer gpa.free(framed);

    for (0..2000) |_| {
        try d.push(gpa, framed);
        try testing.expectEqualStrings("0123456789", (try d.next()).?);
    }
    // Compaction on push keeps this at one message, not two thousand.
    try testing.expect(d.buf.capacity < 1024);
}
