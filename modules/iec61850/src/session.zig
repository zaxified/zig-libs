// SPDX-License-Identifier: MIT

//! The ISO 8327-1 **session layer** — the first of the three OSI layers an MMS
//! association has to climb through before a single byte of IEC 61850 is
//! exchanged, and the one most often skipped over as "that constant prefix".
//!
//! It is not a constant prefix. Three shapes matter:
//!
//! * **CONNECT (SI 13) / ACCEPT (SI 14)** carry a nested parameter tree: PGIs
//!   (parameter groups) that contain PIs (parameters), each `code, length,
//!   value`. The Connect/Accept Item PGI (5) holds the protocol options and the
//!   version; the session selectors and the user requirements sit at the top
//!   level; the presentation CP-PPDU rides in the User Data PGI (193).
//! * **Data transfer is two concatenated SPDUs**, not one: `GIVE TOKENS`
//!   (SI 1, LI 0) immediately followed by `DATA TRANSFER` (SI 1, LI 0), i.e.
//!   the four octets `01 00 01 00` in front of every presentation PDU. An
//!   implementation that emits only one of them wedges a real peer.
//! * **`LI == 255` is an escape**, not a length: the real 16-bit length
//!   follows. Any parameter body over 254 octets uses it, which a large
//!   presentation CP with many contexts will.
//!
//! Decoded parameter bodies are kept as raw slices so a CONNECT re-encodes to
//! the identical octets whatever order a peer put its parameters in.

const std = @import("std");

pub const Error = error{
    ShortSpdu,
    /// The length indicator points past the octets present.
    BadLength,
    UnknownSpduType,
    /// A parameter whose length runs off the end of its group.
    BadParameter,
    /// A CONNECT/ACCEPT with no User Data parameter — there is nothing above
    /// it to hand up.
    MissingUserData,
    /// Not the SPDU the caller required.
    UnexpectedSpdu,
    BufferTooSmall,
};

/// SPDU identifiers. `GIVE TOKENS` and `DATA TRANSFER` genuinely share SI 1 —
/// they are told apart by concatenation, which is why `data_transfer_prefix`
/// exists rather than a third enum member.
pub const Spdu = enum(u8) {
    give_tokens_or_data = 1,
    please_tokens = 2,
    not_finished = 8,
    finish = 9,
    disconnect = 10,
    refuse = 12,
    connect = 13,
    accept = 14,
    abort = 25,
    abort_accept = 26,
    _,
};

/// Parameter (PI) and parameter-group (PGI) codes.
pub const Pi = struct {
    pub const connect_accept_item: u8 = 5;
    pub const transport_disconnect: u8 = 17;
    pub const protocol_options: u8 = 19;
    pub const tsdu_maximum_size: u8 = 21;
    pub const version_number: u8 = 22;
    pub const initial_serial_number: u8 = 23;
    pub const token_setting_item: u8 = 26;
    pub const session_user_requirements: u8 = 20;
    pub const enclosure_item: u8 = 25;
    pub const calling_session_selector: u8 = 51;
    pub const called_session_selector: u8 = 52;
    pub const second_initial_serial_number: u8 = 55;
    pub const data_overflow: u8 = 60;
    pub const user_data: u8 = 193;
    pub const extended_user_data: u8 = 194;
};

/// The four octets that precede every presentation PDU once the association is
/// up: GIVE TOKENS (SI 1, LI 0) then DATA TRANSFER (SI 1, LI 0).
pub const data_transfer_prefix = [_]u8{ 0x01, 0x00, 0x01, 0x00 };

pub const Parameter = struct { code: u8, value: []const u8 };

/// Walks a parameter (or parameter-group) body.
pub const ParamIterator = struct {
    rest: []const u8,

    pub fn next(self: *ParamIterator) Error!?Parameter {
        if (self.rest.len == 0) return null;
        if (self.rest.len < 2) return error.BadParameter;
        const code = self.rest[0];
        var len: usize = self.rest[1];
        var off: usize = 2;
        if (len == 255) {
            // ISO 8327 §8.2: LI 255 escapes to a 16-bit length.
            if (self.rest.len < 4) return error.BadParameter;
            len = (@as(usize, self.rest[2]) << 8) | self.rest[3];
            off = 4;
        }
        if (self.rest.len < off + len) return error.BadParameter;
        const value = self.rest[off .. off + len];
        self.rest = self.rest[off + len ..];
        return .{ .code = code, .value = value };
    }
};

/// A decoded CONNECT or ACCEPT SPDU.
pub const Connect = struct {
    spdu: Spdu,
    /// Everything after the SPDU header, kept for a verbatim re-encode.
    params: []const u8,
    protocol_options: ?u8 = null,
    version_number: ?u8 = null,
    session_user_requirements: ?u16 = null,
    calling_selector: ?[]const u8 = null,
    called_selector: ?[]const u8 = null,
    /// The presentation PDU.
    user_data: []const u8 = &.{},
    total_len: usize = 0,
};

/// Reads the SPDU header, returning the type, the parameter body and how many
/// octets the whole SPDU occupies.
pub fn decodeHeader(bytes: []const u8) Error!struct { spdu: Spdu, params: []const u8, total_len: usize } {
    if (bytes.len < 2) return error.ShortSpdu;
    const si: Spdu = @enumFromInt(bytes[0]);
    var len: usize = bytes[1];
    var off: usize = 2;
    if (len == 255) {
        if (bytes.len < 4) return error.ShortSpdu;
        len = (@as(usize, bytes[2]) << 8) | bytes[3];
        off = 4;
    }
    if (bytes.len < off + len) return error.BadLength;
    return .{ .spdu = si, .params = bytes[off .. off + len], .total_len = off + len };
}

pub fn decodeConnect(bytes: []const u8) Error!Connect {
    const h = try decodeHeader(bytes);
    switch (h.spdu) {
        .connect, .accept, .refuse => {},
        else => return error.UnexpectedSpdu,
    }
    var c = Connect{ .spdu = h.spdu, .params = h.params, .total_len = h.total_len };
    var found_user_data = false;
    var it = ParamIterator{ .rest = h.params };
    while (try it.next()) |p| {
        switch (p.code) {
            Pi.connect_accept_item => {
                var inner = ParamIterator{ .rest = p.value };
                while (try inner.next()) |q| {
                    switch (q.code) {
                        Pi.protocol_options => if (q.value.len == 1) {
                            c.protocol_options = q.value[0];
                        },
                        Pi.version_number => if (q.value.len == 1) {
                            c.version_number = q.value[0];
                        },
                        else => {},
                    }
                }
            },
            Pi.session_user_requirements => if (p.value.len == 2) {
                c.session_user_requirements = std.mem.readInt(u16, p.value[0..2], .big);
            },
            Pi.calling_session_selector => c.calling_selector = p.value,
            Pi.called_session_selector => c.called_selector = p.value,
            Pi.user_data, Pi.extended_user_data => {
                c.user_data = p.value;
                found_user_data = true;
            },
            else => {},
        }
    }
    if (!found_user_data) return error.MissingUserData;
    return c;
}

/// Session-selector and requirement values a caller can override. The defaults
/// are what both captured IEC 61850 stacks emitted.
pub const ConnectOptions = struct {
    /// Bit 1 (value 2) = duplex functional unit, the only one MMS needs.
    session_user_requirements: u16 = 0x0002,
    protocol_options: u8 = 0x00,
    version_number: u8 = 0x02,
    calling_selector: []const u8 = &[_]u8{ 0x00, 0x01 },
    called_selector: []const u8 = &[_]u8{ 0x00, 0x01 },
};

/// Builds a CONNECT SPDU around a presentation PDU.
pub fn encodeConnect(user_data: []const u8, opts: ConnectOptions, out: []u8) Error![]u8 {
    var body: [512]u8 = undefined;
    var n: usize = 0;
    n += try putGroup(body[n..], Pi.connect_accept_item, &[_]Parameter{
        .{ .code = Pi.protocol_options, .value = &[_]u8{opts.protocol_options} },
        .{ .code = Pi.version_number, .value = &[_]u8{opts.version_number} },
    });
    var sur: [2]u8 = undefined;
    std.mem.writeInt(u16, &sur, opts.session_user_requirements, .big);
    n += try putParam(body[n..], Pi.session_user_requirements, &sur);
    n += try putParam(body[n..], Pi.calling_session_selector, opts.calling_selector);
    n += try putParam(body[n..], Pi.called_session_selector, opts.called_selector);
    return assemble(.connect, body[0..n], user_data, out);
}

/// Builds an ACCEPT SPDU around a presentation PDU. The captured server echoed
/// only the *called* selector, which is what this reproduces.
pub fn encodeAccept(user_data: []const u8, opts: ConnectOptions, out: []u8) Error![]u8 {
    var body: [512]u8 = undefined;
    var n: usize = 0;
    n += try putGroup(body[n..], Pi.connect_accept_item, &[_]Parameter{
        .{ .code = Pi.protocol_options, .value = &[_]u8{opts.protocol_options} },
        .{ .code = Pi.version_number, .value = &[_]u8{opts.version_number} },
    });
    var sur: [2]u8 = undefined;
    std.mem.writeInt(u16, &sur, opts.session_user_requirements, .big);
    n += try putParam(body[n..], Pi.session_user_requirements, &sur);
    n += try putParam(body[n..], Pi.called_session_selector, opts.called_selector);
    return assemble(.accept, body[0..n], user_data, out);
}

/// Builds an ABORT SPDU carrying a presentation ARU-PPDU. `reason` is the
/// Transport Disconnect parameter; `0x0b` is what the captured client sent.
pub fn encodeAbort(user_data: []const u8, reason: u8, out: []u8) Error![]u8 {
    var body: [8]u8 = undefined;
    const n = try putParam(&body, Pi.transport_disconnect, &[_]u8{reason});
    return assemble(.abort, body[0..n], user_data, out);
}

fn assemble(spdu: Spdu, params: []const u8, user_data: []const u8, out: []u8) Error![]u8 {
    const ud_head: usize = if (user_data.len > 254) 4 else 2;
    const total_params = params.len + ud_head + user_data.len;
    const head: usize = if (total_params > 254) 4 else 2;
    if (out.len < head + total_params) return error.BufferTooSmall;
    var w: usize = 0;
    out[w] = @intFromEnum(spdu);
    w += 1;
    if (head == 2) {
        out[w] = @intCast(total_params);
        w += 1;
    } else {
        out[w] = 255;
        out[w + 1] = @intCast((total_params >> 8) & 0xFF);
        out[w + 2] = @intCast(total_params & 0xFF);
        w += 3;
    }
    @memcpy(out[w..][0..params.len], params);
    w += params.len;
    w += try putParam(out[w..], Pi.user_data, user_data);
    return out[0..w];
}

fn putParam(out: []u8, code: u8, value: []const u8) Error!usize {
    if (value.len > 254) {
        if (out.len < 4 + value.len) return error.BufferTooSmall;
        out[0] = code;
        out[1] = 255;
        out[2] = @intCast((value.len >> 8) & 0xFF);
        out[3] = @intCast(value.len & 0xFF);
        @memcpy(out[4..][0..value.len], value);
        return 4 + value.len;
    }
    if (out.len < 2 + value.len) return error.BufferTooSmall;
    out[0] = code;
    out[1] = @intCast(value.len);
    @memcpy(out[2..][0..value.len], value);
    return 2 + value.len;
}

fn putGroup(out: []u8, code: u8, members: []const Parameter) Error!usize {
    var inner: [128]u8 = undefined;
    var n: usize = 0;
    for (members) |m| n += try putParam(inner[n..], m.code, m.value);
    return putParam(out, code, inner[0..n]);
}

// ── data transfer ───────────────────────────────────────────────────────────

/// Strips the GIVE TOKENS + DATA TRANSFER pair, returning the presentation PDU.
pub fn decodeDataTransfer(bytes: []const u8) Error![]const u8 {
    if (bytes.len < data_transfer_prefix.len) return error.ShortSpdu;
    if (!std.mem.eql(u8, bytes[0..4], &data_transfer_prefix)) return error.UnexpectedSpdu;
    return bytes[4..];
}

pub fn encodeDataTransfer(payload: []const u8, out: []u8) Error![]u8 {
    if (out.len < 4 + payload.len) return error.BufferTooSmall;
    @memcpy(out[0..4], &data_transfer_prefix);
    @memcpy(out[4..][0..payload.len], payload);
    return out[0 .. 4 + payload.len];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The session CONNECT header a real IEC 61850 client sent, with the
/// presentation payload replaced by a two-octet stand-in.
const short_connect = [_]u8{
    0x0D, 0x18, // CONNECT, LI 24
    0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, // Connect/Accept item
    0x14, 0x02, 0x00, 0x02, // session user requirements = duplex
    0x33, 0x02, 0x00, 0x01, // calling selector
    0x34, 0x02, 0x00, 0x01, // called selector
    0xC1, 0x02, 0xAA, 0xBB, // user data
};

test "the captured CONNECT parameter tree decodes" {
    const c = try decodeConnect(&short_connect);
    try testing.expectEqual(Spdu.connect, c.spdu);
    try testing.expectEqual(@as(u8, 0x00), c.protocol_options.?);
    try testing.expectEqual(@as(u8, 0x02), c.version_number.?);
    try testing.expectEqual(@as(u16, 0x0002), c.session_user_requirements.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, c.calling_selector.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, c.called_selector.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, c.user_data);
    try testing.expectEqual(short_connect.len, c.total_len);
}

test "encodeConnect reproduces the captured parameter octets" {
    var out: [64]u8 = undefined;
    const built = try encodeConnect(&[_]u8{ 0xAA, 0xBB }, .{}, &out);
    try testing.expectEqualSlices(u8, &short_connect, built);
}

test "the data transfer prefix is two SPDUs, not one" {
    var out: [16]u8 = undefined;
    const built = try encodeDataTransfer(&[_]u8{ 0x61, 0x02, 0x30, 0x00 }, &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01, 0x00, 0x61, 0x02, 0x30, 0x00 }, built);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x61, 0x02, 0x30, 0x00 }, try decodeDataTransfer(built));
    // A single GIVE TOKENS with no DATA TRANSFER behind it is refused.
    try testing.expectError(error.UnexpectedSpdu, decodeDataTransfer(&[_]u8{ 0x01, 0x00, 0x02, 0x00, 0x61 }));
    try testing.expectError(error.ShortSpdu, decodeDataTransfer(&[_]u8{ 0x01, 0x00 }));
}

test "the LI 255 escape carries a 16-bit length" {
    var big: [600]u8 = undefined;
    var out: [1024]u8 = undefined;
    @memset(&big, 0x5A);
    const built = try encodeConnect(&big, .{}, &out);
    try testing.expectEqual(@as(u8, 0x0D), built[0]);
    try testing.expectEqual(@as(u8, 255), built[1]);
    const c = try decodeConnect(built);
    try testing.expectEqualSlices(u8, &big, c.user_data);
    // The User Data parameter itself also had to escape.
    var it = ParamIterator{ .rest = c.params };
    var saw_long = false;
    while (try it.next()) |p| {
        if (p.code == Pi.user_data and p.value.len == 600) saw_long = true;
    }
    try testing.expect(saw_long);
}

test "malformed session PDUs are typed errors" {
    try testing.expectError(error.ShortSpdu, decodeConnect(&[_]u8{0x0D}));
    try testing.expectError(error.BadLength, decodeConnect(&[_]u8{ 0x0D, 0x20, 0x00 }));
    try testing.expectError(error.UnexpectedSpdu, decodeConnect(&[_]u8{ 0x09, 0x00 }));
    // A CONNECT with no User Data parameter.
    try testing.expectError(error.MissingUserData, decodeConnect(&[_]u8{ 0x0D, 0x04, 0x14, 0x02, 0x00, 0x02 }));
    // A parameter whose length runs past its group.
    try testing.expectError(error.BadParameter, decodeConnect(&[_]u8{ 0x0D, 0x04, 0x14, 0x08, 0x00, 0x02 }));
    // A dangling parameter code.
    try testing.expectError(error.BadParameter, decodeConnect(&[_]u8{ 0x0D, 0x01, 0x14 }));
}

test "abort carries its transport-disconnect reason" {
    var out: [64]u8 = undefined;
    const built = try encodeAbort(&[_]u8{ 0xA0, 0x00 }, 0x0B, &out);
    try testing.expectEqual(@as(u8, 25), built[0]);
    const h = try decodeHeader(built);
    try testing.expectEqual(Spdu.abort, h.spdu);
    var it = ParamIterator{ .rest = h.params };
    var reason: ?u8 = null;
    var ud: []const u8 = &.{};
    while (try it.next()) |p| {
        if (p.code == Pi.transport_disconnect and p.value.len == 1) reason = p.value[0];
        if (p.code == Pi.user_data) ud = p.value;
    }
    try testing.expectEqual(@as(u8, 0x0B), reason.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xA0, 0x00 }, ud);
}

test "fuzz: session decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = decodeConnect(buf[0..len]) catch {};
    _ = decodeDataTransfer(buf[0..len]) catch {};
    const h = decodeHeader(buf[0..len]) catch return;
    try testing.expect(h.total_len <= len);
    var it = ParamIterator{ .rest = h.params };
    var guard: usize = 0;
    while (true) {
        guard += 1;
        try testing.expect(guard <= buf.len + 1);
        const p = it.next() catch return;
        if (p == null) break;
    }
}
