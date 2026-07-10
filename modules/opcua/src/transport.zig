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
        _ = t;
        @panic("TODO(agent): map to its 3-byte ASCII code per OPC 10000-6 §7.1 Table 26");
    }

    /// Parse a wire code back to a `MessageType`, or `null` if unrecognized.
    pub fn fromCode(bytes: *const [3]u8) ?MessageType {
        _ = bytes;
        @panic("TODO(agent): parse the 3-byte ASCII code per OPC 10000-6 §7.1 Table 26");
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
    /// resets the assembler and surfaces `error.MessageTooLarge` — TODO(agent):
    /// reconsider the abort error shape once the caller-facing API around
    /// this is fleshed out.
    pub fn feed(a: *MessageChunkAssembler, chunk_type: ChunkType, body: []const u8) TransportError!?[]const u8 {
        _ = a;
        _ = chunk_type;
        _ = body;
        @panic("TODO(agent): append `body` to `a.buf[a.len..]`, growing `a.len`; on .final return the accumulated slice, on .intermediate return null, on .abort reset and error, per OPC 10000-6 §6.7.2");
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
        _ = c;
        _ = request;
        @panic("TODO(agent): serialize `request` as a single HEL chunk (encoding.Encoder over c.writer), flush, then read+parse the ACK/ERR reply chunk, per OPC 10000-6 §7.1.2/§7.1.3");
    }

    /// Write one message chunk: the 8-byte `MessageHeader` (with
    /// `message_size` computed from `body.len`) followed by `body` verbatim.
    /// `body` already includes any SecureConversationMessageHeader/
    /// SequenceHeader bytes the message type requires.
    pub fn sendChunk(c: *Connection, header: MessageHeader, body: []const u8) TransportError!void {
        _ = c;
        _ = header;
        _ = body;
        @panic("TODO(agent): write the 8-byte header (3-byte type code + chunk-type byte + little-endian u32 size) then `body`, per OPC 10000-6 §7.1");
    }

    /// Read one message chunk: parse the 8-byte `MessageHeader`, then read
    /// exactly `message_size - 8` bytes of body into `body_buf` (which must be
    /// at least that large — `error.MessageTooLarge` otherwise).
    pub fn recvChunk(c: *Connection, body_buf: []u8) TransportError!struct { header: MessageHeader, body: []u8 } {
        _ = c;
        _ = body_buf;
        @panic("TODO(agent): parse the 8-byte header, validate the message/chunk type, then read `message_size - 8` bytes into `body_buf`, per OPC 10000-6 §7.1");
    }
};

/// Convenience: wire a `Connection` over `reader`/`writer` and perform the
/// Hello/Acknowledge handshake (§7.1.2/§7.1.3) for `endpoint_url` in one call.
/// Equivalent to `Connection.init` followed by `.hello(...)` for callers that
/// don't need to customize the `Hello` request's buffer-size/limit fields.
pub fn connect(reader: *std.Io.Reader, writer: *std.Io.Writer, endpoint_url: []const u8) TransportError!Connection {
    _ = reader;
    _ = writer;
    _ = endpoint_url;
    @panic("TODO(agent): Connection.init(reader, writer) then .hello(...) with a default Hello request naming endpoint_url, per OPC 10000-6 §7.1.2");
}

// ── tests ──

test "MessageHeader / ChunkType are constructible (no I/O invoked)" {
    const testing = std.testing;
    const h: MessageHeader = .{ .message_type = .hello, .chunk_type = .final, .message_size = 32 };
    try testing.expectEqual(MessageType.hello, h.message_type);
    try testing.expectEqual(ChunkType.final, h.chunk_type);
}
