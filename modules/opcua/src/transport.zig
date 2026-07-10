// SPDX-License-Identifier: MIT

//! opc.tcp transport (OPC 10000-6 §7) — the binary framing OPC UA Binary
//! messages ride inside: the Hello/Acknowledge/Error handshake (§7.1) and the
//! chunked message framing (§6.7.2/§6.7.3) that every subsequent MSG/OPN/CLO
//! exchange uses.
//!
//! Transport-agnostic by design: `Connection` takes an already-connected
//! `std.Io.Reader`/`std.Io.Writer` pair in its constructor — this module never
//! opens a socket itself. Wire it to a real TCP connection, a `.fixed` buffer
//! pair for offline tests, or anything else that speaks the same interface.
//!
//! The Hello/Acknowledge/Error handshake bodies are simple enough (five
//! UInt32s plus, for Hello, one String) that they're framed here directly
//! with raw `std.Io.Writer`/`std.Io.Reader` integer helpers rather than
//! through `encoding.Encoder`/`Decoder` — that keeps this file's error set
//! (`TransportError`) free of the codec's `ValueTooLarge`/`BadLength`/etc.
//! variants, which a plain fixed-shape handshake can never produce. Once the
//! service layer (F1-b/c/d) sends real MSG bodies, *those* ride the full
//! `encoding` codec inside the chunk body this module hands back.

const std = @import("std");
const encoding = @import("encoding.zig");

pub const TransportError = std.Io.Reader.Error || std.Io.Writer.Error || error{
    /// The 3-byte message-type code wasn't one of HEL/ACK/ERR/MSG/OPN/CLO.
    BadMessageType,
    /// The chunk-type byte wasn't one of 'F'/'C'/'A'.
    BadChunkType,
    /// `MessageHeader.message_size` exceeds the negotiated buffer/message
    /// size limits (§7.1.2/§7.1.3), or a chunk body overruns the caller's
    /// assembly buffer.
    MessageTooLarge,
    /// The peer sent an "Error" message (§7.1.4) instead of the expected
    /// reply.
    ServerError,
    /// `Acknowledge.protocol_version` is a version this client can't speak.
    ProtocolVersionMismatch,
};

// ── message header (§7.1) ───────────────────────────────────────────────────

/// The 3-byte ASCII message-type code (§7.1 Table 26). `open_secure_channel`/
/// `close_secure_channel`/`message` share the chunking + SequenceHeader shape
/// below; `hello`/`acknowledge`/`error_msg` are single-chunk only.
pub const MessageType = enum {
    hello, // "HEL"
    acknowledge, // "ACK"
    error_msg, // "ERR"
    message, // "MSG"
    open_secure_channel, // "OPN"
    close_secure_channel, // "CLO"

    /// The 3 ASCII bytes this type is spelled as on the wire.
    pub fn code(t: MessageType) *const [3]u8 {
        return switch (t) {
            .hello => "HEL",
            .acknowledge => "ACK",
            .error_msg => "ERR",
            .message => "MSG",
            .open_secure_channel => "OPN",
            .close_secure_channel => "CLO",
        };
    }

    /// Parse a wire code back to a `MessageType`, or `null` if unrecognized.
    pub fn fromCode(bytes: *const [3]u8) ?MessageType {
        const eql = std.mem.eql;
        if (eql(u8, bytes, "HEL")) return .hello;
        if (eql(u8, bytes, "ACK")) return .acknowledge;
        if (eql(u8, bytes, "ERR")) return .error_msg;
        if (eql(u8, bytes, "MSG")) return .message;
        if (eql(u8, bytes, "OPN")) return .open_secure_channel;
        if (eql(u8, bytes, "CLO")) return .close_secure_channel;
        return null;
    }
};

/// The chunk-type byte, the 4th byte of the 8-byte MessageHeader (§7.1 /
/// §6.7.2): whether this chunk is the last one, a continuation, or an abort.
pub const ChunkType = enum(u8) {
    /// 'F' — the final chunk of the message.
    final = 'F',
    /// 'C' — an intermediate chunk; more follow.
    intermediate = 'C',
    /// 'A' — abort: discard every chunk gathered so far for this message.
    abort = 'A',
};

/// The 8-byte header prefixing every opc.tcp message chunk (§7.1): a 3-byte
/// message-type code, a 1-byte chunk-type, and a 4-byte (little-endian) total
/// chunk size *including this header*.
pub const MessageHeader = struct {
    message_type: MessageType,
    chunk_type: ChunkType,
    /// Total size of this chunk in bytes, header included.
    message_size: u32,
};

/// Size of the fixed `MessageHeader` on the wire (§7.1): 3-byte type code +
/// 1-byte chunk type + 4-byte little-endian size.
const header_size: u32 = 8;

// ── Hello / Acknowledge / Error bodies (§7.1.2-7.1.4) ───────────────────────

/// The client's opening handshake message (§7.1.2), sent as a single "HEL"
/// chunk. `endpoint_url` names the opc.tcp endpoint being connected to.
pub const Hello = struct {
    protocol_version: u32,
    receive_buffer_size: u32,
    send_buffer_size: u32,
    max_message_size: u32,
    max_chunk_count: u32,
    endpoint_url: []const u8,
};

/// The server's handshake reply (§7.1.3), negotiating the connection limits
/// the rest of the session is bound by.
pub const Acknowledge = struct {
    protocol_version: u32,
    receive_buffer_size: u32,
    send_buffer_size: u32,
    max_message_size: u32,
    max_chunk_count: u32,
};

/// Sent by either side to report a transport-level failure and close the
/// connection (§7.1.4).
pub const Error = struct {
    error_code: encoding.StatusCode,
    reason: ?[]const u8,
};

// ── secure-conversation framing (§6.7.2 / §6.7.3) ───────────────────────────

/// The extended header present (after the 8-byte `MessageHeader`) on every
/// MSG/OPN/CLO chunk (§6.7.2): which secure channel this chunk belongs to.
/// `SecureChannel` (root.zig, F1-b) owns assigning/validating this id;
/// SecurityMode=None means no signature/encryption ride along with it here.
pub const SecureConversationMessageHeader = struct {
    secure_channel_id: u32,
};

/// Per-chunk sequencing (§6.7.3): a monotonically increasing sequence number
/// (detects dropped/reordered chunks) and the client-assigned request id that
/// correlates a request's chunks with its response's.
pub const SequenceHeader = struct {
    sequence_number: u32,
    request_id: u32,
};

/// Reassembles a run of MSG/OPN/CLO chunks (chunk types 'C' then a final 'F',
/// or a lone 'F') sharing one `SecureConversationMessageHeader.
/// secure_channel_id` into a single logical message body (§6.7.2). An abort
/// chunk ('A') discards everything gathered so far.
pub const MessageChunkAssembler = struct {
    /// Caller-owned scratch buffer; reassembled bytes accumulate here.
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8) MessageChunkAssembler {
        return .{ .buf = buf };
    }

    pub fn reset(a: *MessageChunkAssembler) void {
        a.len = 0;
    }

    /// Feed one chunk's body (the bytes after its `SequenceHeader`). Returns
    /// the complete message once a final ('F') chunk lands; `null` while more
    /// intermediate ('C') chunks are still expected. An abort ('A') chunk
    /// resets the assembler and surfaces `error.MessageTooLarge` (the closest
    /// fit in this module's error set — the caller is expected to treat an
    /// abort as "this exchange failed", the same way it treats an oversize
    /// chunk).
    pub fn feed(a: *MessageChunkAssembler, chunk_type: ChunkType, body: []const u8) TransportError!?[]const u8 {
        switch (chunk_type) {
            .abort => {
                a.reset();
                return error.MessageTooLarge;
            },
            .intermediate, .final => {
                if (a.len + body.len > a.buf.len) return error.MessageTooLarge;
                @memcpy(a.buf[a.len..][0..body.len], body);
                a.len += body.len;
                if (chunk_type == .final) {
                    const result = a.buf[0..a.len];
                    a.reset();
                    return result;
                }
                return null;
            },
        }
    }
};

// ── Connection ───────────────────────────────────────────────────────────────

/// A caller-driven opc.tcp connection over an already-established byte stream
/// — a TCP socket's buffered reader/writer, an in-memory `.fixed` pair for
/// tests, anything. This module never opens a socket: the caller owns
/// connecting/TLS-terminating/whatever transport underneath and just hands
/// over the two ends.
pub const Connection = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,

    pub fn init(reader: *std.Io.Reader, writer: *std.Io.Writer) Connection {
        return .{ .reader = reader, .writer = writer };
    }

    /// Send the client "Hello" (§7.1.2) and block for the server's
    /// "Acknowledge" (or surface its "Error" as `error.ServerError`).
    pub fn hello(c: *Connection, request: Hello) TransportError!Acknowledge {
        if (request.endpoint_url.len > std.math.maxInt(i32)) return error.MessageTooLarge;

        // Hello body: 5x UInt32 + one String (Int32 length + UTF-8 bytes).
        var body_buf: [512]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body_buf);
        try bw.writeInt(u32, request.protocol_version, .little);
        try bw.writeInt(u32, request.receive_buffer_size, .little);
        try bw.writeInt(u32, request.send_buffer_size, .little);
        try bw.writeInt(u32, request.max_message_size, .little);
        try bw.writeInt(u32, request.max_chunk_count, .little);
        try bw.writeInt(i32, @intCast(request.endpoint_url.len), .little);
        try bw.writeAll(request.endpoint_url);
        const body = bw.buffered();
        if (body.len > std.math.maxInt(u32) - header_size) return error.MessageTooLarge;

        try c.sendChunk(.{ .message_type = .hello, .chunk_type = .final, .message_size = header_size + @as(u32, @intCast(body.len)) }, body);
        try c.writer.flush();

        var recv_buf: [512]u8 = undefined;
        const chunk = try c.recvChunk(&recv_buf);
        if (chunk.header.message_type == .error_msg) return error.ServerError;
        if (chunk.header.message_type != .acknowledge) return error.BadMessageType;
        if (chunk.header.chunk_type != .final) return error.BadChunkType;
        if (chunk.body.len != 20) return error.MessageTooLarge; // 5x UInt32

        var br: std.Io.Reader = .fixed(chunk.body);
        const ack: Acknowledge = .{
            .protocol_version = try br.takeInt(u32, .little),
            .receive_buffer_size = try br.takeInt(u32, .little),
            .send_buffer_size = try br.takeInt(u32, .little),
            .max_message_size = try br.takeInt(u32, .little),
            .max_chunk_count = try br.takeInt(u32, .little),
        };

        // F1 speaks exactly one protocol version (0, the only one that has
        // ever existed on the wire); a server answering with anything else
        // is a version this client can't speak.
        if (ack.protocol_version != request.protocol_version) return error.ProtocolVersionMismatch;

        return ack;
    }

    /// Write one message chunk: the 8-byte `MessageHeader` (with
    /// `message_size` computed from `body.len`) followed by `body` verbatim.
    /// `body` already includes any SecureConversationMessageHeader/
    /// SequenceHeader bytes the message type requires.
    pub fn sendChunk(c: *Connection, header: MessageHeader, body: []const u8) TransportError!void {
        try c.writer.writeAll(header.message_type.code());
        try c.writer.writeByte(@intFromEnum(header.chunk_type));
        try c.writer.writeInt(u32, header.message_size, .little);
        try c.writer.writeAll(body);
    }

    /// Read one message chunk: parse the 8-byte `MessageHeader`, then read
    /// exactly `message_size - 8` bytes of body into `body_buf` (which must be
    /// at least that large — `error.MessageTooLarge` otherwise).
    pub fn recvChunk(c: *Connection, body_buf: []u8) TransportError!struct { header: MessageHeader, body: []u8 } {
        const type_bytes = (try c.reader.takeArray(3)).*;
        const chunk_byte = try c.reader.takeByte();
        const size = try c.reader.takeInt(u32, .little);

        const message_type = MessageType.fromCode(&type_bytes) orelse return error.BadMessageType;
        const chunk_type = std.enums.fromInt(ChunkType, chunk_byte) orelse return error.BadChunkType;
        if (size < header_size) return error.BadMessageType;

        const body_len = size - header_size;
        if (body_len > body_buf.len) return error.MessageTooLarge;
        const body = body_buf[0..body_len];
        try c.reader.readSliceAll(body);

        return .{
            .header = .{ .message_type = message_type, .chunk_type = chunk_type, .message_size = size },
            .body = body,
        };
    }
};

/// Convenience: wire a `Connection` over `reader`/`writer` and perform the
/// Hello/Acknowledge handshake (§7.1.2/§7.1.3) for `endpoint_url` in one call.
/// Equivalent to `Connection.init` followed by `.hello(...)` for callers that
/// don't need to customize the `Hello` request's buffer-size/limit fields.
pub fn connect(reader: *std.Io.Reader, writer: *std.Io.Writer, endpoint_url: []const u8) TransportError!Connection {
    var conn = Connection.init(reader, writer);
    _ = try conn.hello(.{
        .protocol_version = 0,
        .receive_buffer_size = 65536,
        .send_buffer_size = 65536,
        .max_message_size = 0, // 0 = no limit, per OPC 10000-6 §7.1.2
        .max_chunk_count = 0, // 0 = no limit
        .endpoint_url = endpoint_url,
    });
    return conn;
}

// ── tests ──

test "MessageHeader / ChunkType are constructible (no I/O invoked)" {
    const testing = std.testing;
    const h: MessageHeader = .{ .message_type = .hello, .chunk_type = .final, .message_size = 32 };
    try testing.expectEqual(MessageType.hello, h.message_type);
    try testing.expectEqual(ChunkType.final, h.chunk_type);
}

test "MessageType.code / fromCode round-trip" {
    const testing = std.testing;
    const all_types = [_]MessageType{ .hello, .acknowledge, .error_msg, .message, .open_secure_channel, .close_secure_channel };
    inline for (all_types) |mt| {
        const code = mt.code();
        try testing.expectEqual(@as(?MessageType, mt), MessageType.fromCode(code));
    }
    try testing.expectEqual(@as(?MessageType, null), MessageType.fromCode("XXX"));
}

test "sendChunk / recvChunk round-trip over an in-memory pipe" {
    const testing = std.testing;
    var pipe_buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&pipe_buf);
    var c_write = Connection.init(undefined, &w);
    try c_write.sendChunk(.{ .message_type = .message, .chunk_type = .final, .message_size = 8 + 4 }, "abcd");

    var r: std.Io.Reader = .fixed(w.buffered());
    var c_read = Connection.init(&r, undefined);
    var body_buf: [64]u8 = undefined;
    const chunk = try c_read.recvChunk(&body_buf);
    try testing.expectEqual(MessageType.message, chunk.header.message_type);
    try testing.expectEqual(ChunkType.final, chunk.header.chunk_type);
    try testing.expectEqualSlices(u8, "abcd", chunk.body);
}

test "Connection.hello: HEL/ACK handshake over an in-memory pipe" {
    const testing = std.testing;

    // Client -> server pipe (the Hello) and server -> client pipe (the Ack)
    // are modeled as two independent fixed buffers since `.fixed` readers/
    // writers aren't full-duplex sockets.
    var hel_buf: [256]u8 = undefined;
    var hel_w: std.Io.Writer = .fixed(&hel_buf);

    // First, act as the client and write the Hello into `hel_w`.
    {
        var client = Connection.init(undefined, &hel_w);
        var body_buf: [512]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&body_buf);
        try bw.writeInt(u32, 0, .little);
        try bw.writeInt(u32, 65536, .little);
        try bw.writeInt(u32, 65536, .little);
        try bw.writeInt(u32, 0, .little);
        try bw.writeInt(u32, 0, .little);
        try bw.writeInt(i32, 18, .little);
        try bw.writeAll("opc.tcp://a:4840/");
        const body = bw.buffered();
        try client.sendChunk(.{ .message_type = .hello, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(body.len)) }, body);
    }

    // Act as the server: parse the Hello, build an Acknowledge.
    var hel_r: std.Io.Reader = .fixed(hel_w.buffered());
    var server = Connection.init(&hel_r, undefined);
    var srv_body_buf: [512]u8 = undefined;
    const hel_chunk = try server.recvChunk(&srv_body_buf);
    try testing.expectEqual(MessageType.hello, hel_chunk.header.message_type);
    var hel_body_r: std.Io.Reader = .fixed(hel_chunk.body);
    const client_protocol_version = try hel_body_r.takeInt(u32, .little);
    try testing.expectEqual(@as(u32, 0), client_protocol_version);

    // Now drive the full client-side `hello()` against a canned Ack reply.
    var ack_buf: [64]u8 = undefined;
    var ack_w: std.Io.Writer = .fixed(&ack_buf);
    var ack_conn = Connection.init(undefined, &ack_w);
    var ack_body_buf: [64]u8 = undefined;
    var ack_bw: std.Io.Writer = .fixed(&ack_body_buf);
    try ack_bw.writeInt(u32, 0, .little);
    try ack_bw.writeInt(u32, 8192, .little);
    try ack_bw.writeInt(u32, 8192, .little);
    try ack_bw.writeInt(u32, 0, .little);
    try ack_bw.writeInt(u32, 0, .little);
    const ack_body = ack_bw.buffered();
    try ack_conn.sendChunk(.{ .message_type = .acknowledge, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(ack_body.len)) }, ack_body);

    var client_hel_out: [256]u8 = undefined;
    var client_w: std.Io.Writer = .fixed(&client_hel_out);
    var client_r: std.Io.Reader = .fixed(ack_w.buffered());
    var client = Connection.init(&client_r, &client_w);
    const ack = try client.hello(.{
        .protocol_version = 0,
        .receive_buffer_size = 65536,
        .send_buffer_size = 65536,
        .max_message_size = 0,
        .max_chunk_count = 0,
        .endpoint_url = "opc.tcp://a:4840/",
    });
    try testing.expectEqual(@as(u32, 8192), ack.receive_buffer_size);
    try testing.expectEqual(@as(u32, 8192), ack.send_buffer_size);
}

test "Connection.hello: server Error reply surfaces error.ServerError" {
    const testing = std.testing;
    var err_buf: [64]u8 = undefined;
    var err_w: std.Io.Writer = .fixed(&err_buf);
    var err_conn = Connection.init(undefined, &err_w);
    var err_body_buf: [16]u8 = undefined;
    var err_bw: std.Io.Writer = .fixed(&err_body_buf);
    try err_bw.writeInt(u32, 0x80010000, .little); // BadUnexpectedError-ish
    try err_bw.writeInt(i32, -1, .little); // null reason string
    const err_body = err_bw.buffered();
    try err_conn.sendChunk(.{ .message_type = .error_msg, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(err_body.len)) }, err_body);

    var out_buf: [256]u8 = undefined;
    var out_w: std.Io.Writer = .fixed(&out_buf);
    var in_r: std.Io.Reader = .fixed(err_w.buffered());
    var client = Connection.init(&in_r, &out_w);
    try testing.expectError(error.ServerError, client.hello(.{
        .protocol_version = 0,
        .receive_buffer_size = 65536,
        .send_buffer_size = 65536,
        .max_message_size = 0,
        .max_chunk_count = 0,
        .endpoint_url = "opc.tcp://a:4840/",
    }));
}

test "MessageChunkAssembler: multi-chunk reassembly" {
    const testing = std.testing;
    var scratch: [16]u8 = undefined;
    var a = MessageChunkAssembler.init(&scratch);
    try testing.expectEqual(@as(?[]const u8, null), try a.feed(.intermediate, "ab"));
    try testing.expectEqual(@as(?[]const u8, null), try a.feed(.intermediate, "cd"));
    const result = try a.feed(.final, "ef");
    try testing.expectEqualSlices(u8, "abcdef", result.?);

    // Assembler is reusable for the next message after a final chunk.
    const result2 = try a.feed(.final, "xyz");
    try testing.expectEqualSlices(u8, "xyz", result2.?);
}

test "MessageChunkAssembler: abort resets and errors" {
    const testing = std.testing;
    var scratch: [16]u8 = undefined;
    var a = MessageChunkAssembler.init(&scratch);
    _ = try a.feed(.intermediate, "ab");
    try testing.expectError(error.MessageTooLarge, a.feed(.abort, ""));
    try testing.expectEqual(@as(usize, 0), a.len);
    // Assembler is usable again after an abort.
    const result = try a.feed(.final, "ok");
    try testing.expectEqualSlices(u8, "ok", result.?);
}

test "negatives: oversize chunk body surfaces MessageTooLarge" {
    const testing = std.testing;
    var scratch: [4]u8 = undefined;
    var a = MessageChunkAssembler.init(&scratch);
    try testing.expectError(error.MessageTooLarge, a.feed(.final, "too many bytes"));
}

test "negatives: bad message type / bad chunk type in recvChunk" {
    const testing = std.testing;
    {
        var buf = [_]u8{ 'X', 'X', 'X', 'F', 0, 0, 0, 0 };
        var r: std.Io.Reader = .fixed(&buf);
        var c = Connection.init(&r, undefined);
        var body_buf: [8]u8 = undefined;
        try testing.expectError(error.BadMessageType, c.recvChunk(&body_buf));
    }
    {
        var buf = [_]u8{ 'M', 'S', 'G', 'Z', 8, 0, 0, 0 };
        var r: std.Io.Reader = .fixed(&buf);
        var c = Connection.init(&r, undefined);
        var body_buf: [8]u8 = undefined;
        try testing.expectError(error.BadChunkType, c.recvChunk(&body_buf));
    }
}

test "negatives: truncated header surfaces EndOfStream, not a panic" {
    const testing = std.testing;
    var buf = [_]u8{ 'H', 'E', 'L' }; // missing chunk-type byte + size
    var r: std.Io.Reader = .fixed(&buf);
    var c = Connection.init(&r, undefined);
    var body_buf: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, c.recvChunk(&body_buf));
}
