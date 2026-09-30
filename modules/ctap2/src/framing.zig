// SPDX-License-Identifier: MIT
//! CTAP2 message framing over an abstract transport (CTAP 2.1 §6):
//!
//!   request  = command byte || CBOR map (the map may be absent)
//!   response = status byte  || CBOR (absent on failure and for commands
//!                                    that return nothing)
//!
//! No device I/O lives here. The caller supplies a `Transport`: one function
//! that sends a complete request message and receives the complete response
//! message (a USB-HID, NFC or BLE binding does its own fragmentation below
//! this line; `ctaphid.zig` is the packet codec for the HID one).

const std = @import("std");
const cbor = @import("cbor");
const status = @import("status.zig");

const Allocator = std.mem.Allocator;

/// Failures of the transport itself, as opposed to a status the authenticator
/// answered with.
pub const TransportError = error{
    /// The device or link failed (unplugged, I/O error, timeout at the link).
    TransportFailed,
    /// The response did not fit the buffer handed to `transact`.
    ResponseBufferTooSmall,
};

/// A synchronous request/response channel to one authenticator.
///
/// `transactFn` sends `request` (command byte || CBOR) and writes the complete
/// response (status byte || CBOR) into `response`, returning its length.
/// Keep-alive handling, channel allocation and fragmentation belong to it.
pub const Transport = struct {
    ctx: *anyopaque,
    transactFn: *const fn (ctx: *anyopaque, request: []const u8, response: []u8) TransportError!usize,

    /// Run one transaction and return the filled prefix of `response`.
    pub fn transact(self: Transport, request: []const u8, response: []u8) TransportError![]u8 {
        const n = try self.transactFn(self.ctx, request, response);
        if (n > response.len) return error.ResponseBufferTooSmall;
        return response[0..n];
    }
};

/// CTAP2 command bytes (CTAP 2.1 §6, §8.1) this module knows by name.
pub const Command = enum(u8) {
    make_credential = 0x01,
    get_assertion = 0x02,
    get_info = 0x04,
    client_pin = 0x06,
    reset = 0x07,
    get_next_assertion = 0x08,
    _,
};

/// What can go wrong parsing a response, beyond a non-zero status byte.
pub const ParseError = error{
    /// A status-OK response that had to carry a CBOR body carried none.
    EmptyResponse,
    /// The body is not one well-formed CBOR item (or nests too deeply).
    MalformedCbor,
    /// A field has a CBOR type other than the one the spec assigns it.
    UnexpectedType,
    /// A required field is absent.
    MissingField,
    /// A map carries the same key twice.
    DuplicateKey,
    /// An integer field is outside the range its use allows.
    ValueOutOfRange,
    /// A byte string has a length the spec does not allow.
    BadLength,
};

pub const CallError = TransportError || status.StatusError || ParseError || Allocator.Error;

/// The success payload of one response: the bytes after the status byte.
pub const Response = struct {
    /// Backing buffer (`deinit` frees it).
    buf: []u8,
    /// `buf` without the status byte; empty for commands that answer with
    /// the status byte only.
    body: []const u8,

    pub fn deinit(self: Response, allocator: Allocator) void {
        allocator.free(self.buf);
    }
};

/// Build `command || CBOR(params)`. `params == null` sends the command byte
/// alone (`authenticatorGetInfo` takes no input). Map keys are emitted in
/// CTAP2 canonical order (§8.1: every key set used here is a small unsigned
/// or negative integer, for which bytewise order of the encoded key and the
/// spec's "shortest first, then bytewise" order coincide).
pub fn encodeRequest(allocator: Allocator, command: u8, params: ?cbor.Value) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, command);
    if (params) |p| {
        const body = try cbor.encode(allocator, p, .{ .canonical = true });
        defer allocator.free(body);
        try out.appendSlice(allocator, body);
    }
    return out.toOwnedSlice(allocator);
}

/// Split a raw response into its status and body. A non-zero status is the
/// typed error; a zero-length message is `EmptyResponse`.
pub fn splitResponse(raw: []const u8) (status.StatusError || ParseError)![]const u8 {
    if (raw.len == 0) return error.EmptyResponse;
    try status.check(raw[0]);
    return raw[1..];
}

/// Send `command || CBOR(params)` and return the successful response body.
/// `max_response` bounds the receive buffer.
pub fn call(
    allocator: Allocator,
    transport: Transport,
    command: u8,
    params: ?cbor.Value,
    max_response: usize,
) CallError!Response {
    const request = try encodeRequest(allocator, command, params);
    defer allocator.free(request);
    const buf = try allocator.alloc(u8, max_response);
    errdefer allocator.free(buf);
    const raw = try transport.transact(request, buf);
    const body = try splitResponse(raw);
    return .{ .buf = buf, .body = body };
}

// ── CBOR map access helpers (shared by the response parsers) ───────────────

/// Decode `body` as exactly one CBOR map and return its entries. The tree is
/// allocated from `allocator` (use an arena).
pub fn decodeMap(allocator: Allocator, body: []const u8) (ParseError || Allocator.Error)![]const cbor.MapEntry {
    if (body.len == 0) return error.EmptyResponse;
    const v = cbor.decode(allocator, body, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedCbor,
    };
    return switch (v) {
        .map => |m| m,
        else => error.UnexpectedType,
    };
}

/// The value stored under unsigned key `key`, `null` if absent; a key that
/// appears twice is `DuplicateKey`. Keys that are not unsigned integers are
/// skipped (unknown extras are tolerated).
pub fn find(entries: []const cbor.MapEntry, key: u64) ParseError!?cbor.Value {
    var found: ?cbor.Value = null;
    for (entries) |e| {
        switch (e.key) {
            .uint => |k| if (k == key) {
                if (found != null) return error.DuplicateKey;
                found = e.value;
            },
            else => {},
        }
    }
    return found;
}

pub fn asUint(v: cbor.Value) ParseError!u64 {
    return switch (v) {
        .uint => |u| u,
        else => error.UnexpectedType,
    };
}

pub fn asBool(v: cbor.Value) ParseError!bool {
    return switch (v) {
        .bool => |b| b,
        else => error.UnexpectedType,
    };
}

pub fn asBytes(v: cbor.Value) ParseError![]const u8 {
    return switch (v) {
        .bytes => |b| b,
        else => error.UnexpectedType,
    };
}

pub fn asU32(v: cbor.Value) ParseError!u32 {
    const u = try asUint(v);
    return std.math.cast(u32, u) orelse error.ValueOutOfRange;
}

test "encodeRequest: command byte alone, and command plus canonical map" {
    const a = std.testing.allocator;
    const only = try encodeRequest(a, 0x04, null);
    defer a.free(only);
    try std.testing.expectEqualSlices(u8, &.{0x04}, only);

    // Keys deliberately out of order: 2 before 1.
    const entries = [_]cbor.MapEntry{
        .{ .key = .{ .uint = 2 }, .value = .{ .uint = 1 } },
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 2 } },
    };
    const req = try encodeRequest(a, 0x06, .{ .map = &entries });
    defer a.free(req);
    try std.testing.expectEqualSlices(u8, &.{ 0x06, 0xa2, 0x01, 0x02, 0x02, 0x01 }, req);
}

test "splitResponse: status byte is stripped, errors are typed" {
    try std.testing.expectEqualSlices(u8, &.{}, try splitResponse(&.{0x00}));
    try std.testing.expectEqualSlices(u8, &.{0xa0}, try splitResponse(&.{ 0x00, 0xa0 }));
    try std.testing.expectError(error.PinInvalid, splitResponse(&.{0x31}));
    try std.testing.expectError(error.PinBlocked, splitResponse(&.{ 0x32, 0xa0 })); // a body after an error is ignored
    try std.testing.expectError(error.EmptyResponse, splitResponse(&.{}));
    try std.testing.expectError(error.UnknownStatus, splitResponse(&.{0xF5}));
}

test "find: absent, present, duplicate and non-integer keys" {
    const entries = [_]cbor.MapEntry{
        .{ .key = .{ .text = "x" }, .value = .{ .uint = 9 } },
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 7 } },
    };
    try std.testing.expectEqual(@as(?cbor.Value, null), try find(&entries, 2));
    try std.testing.expectEqual(@as(u64, 7), try asUint((try find(&entries, 1)).?));
    const dup = [_]cbor.MapEntry{
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 7 } },
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 8 } },
    };
    try std.testing.expectError(error.DuplicateKey, find(&dup, 1));
}
