// SPDX-License-Identifier: MIT

//! modbus — pure-Zig Modbus protocol codec + client (master) for TCP and RTU.
//!
//! Three layers, all allocation-free:
//!
//! - **PDU codec** (`pdu`): transport-independent request encoding and
//!   response parsing for the core public function codes — 0x01 Read Coils,
//!   0x02 Read Discrete Inputs, 0x03 Read Holding Registers, 0x04 Read Input
//!   Registers, 0x05 Write Single Coil, 0x06 Write Single Register,
//!   0x0F Write Multiple Coils, 0x10 Write Multiple Registers,
//!   0x17 Read/Write Multiple Registers. Spec quantity limits are enforced
//!   as typed errors; exception responses (function | 0x80) map to a typed
//!   error set. Registers are big-endian 16-bit; coil bits pack LSB-first.
//! - **ADU framing**: `tcp` (MBAP header — transaction id, protocol id 0,
//!   length, unit id) and `rtu` (address + PDU + CRC-16, poly 0xA001
//!   reflected, low byte first on the wire). ASCII framing is out of scope.
//! - **Client** (`Client`): a master that talks through a caller-provided
//!   `Transport` seam (send request ADU, receive reply ADU), so it is fully
//!   offline-testable. `TcpTransport` is an optional convenience adapter
//!   over `std.Io.net` for real Modbus TCP connections.
//!
//! Malformed, short, or corrupt reply bytes never panic — every decode path
//! returns a typed error (short frame, bad CRC, transaction id / unit /
//! function mismatch, malformed byte counts, exception codes).
//!
//! Broadcast (unit 0, no reply) and server-side (slave) processing are out
//! of scope for now; the PDU codec is reusable for a future server.
//!
//! Provenance: clean-room from the public Modbus Application Protocol
//! Specification V1.1b3 and Modbus over Serial Line Specification V1.02
//! (modbus.org — the protocol is openly published and royalty-free);
//! libmodbus (LGPL-2.1+) referenced for behavior only, no source consulted
//! or copied. Known-answer tests use the worked wire examples from the
//! application-protocol spec.

const std = @import("std");

pub const meta = .{
    .status = .gap, // no mature pure-Zig Modbus library exists
    .platform = .any, // codec + client are portable; TcpTransport uses std.Io.net
    .role = .client, // master + reusable wire codec
    .concurrency = .single_owner, // Client tracks the TCP transaction id
    .model_after = "Modbus Application Protocol V1.1b3 / libmodbus (behavior)",
    .deps = .{}, // std only
};

// ── wire constants ──────────────────────────────────────────────────────────

/// Maximum PDU size (function code + data) per the application spec.
pub const max_pdu_len = 253;

/// Spec quantity limits per function code (Modbus Application Protocol
/// V1.1b3, sections 6.1–6.17). Violations yield `error.InvalidQuantity`.
pub const limits = struct {
    pub const max_read_bits = 2000; // FC 01 / 02
    pub const max_read_registers = 125; // FC 03 / 04
    pub const max_write_bits = 1968; // FC 0F
    pub const max_write_registers = 123; // FC 10
    pub const max_rw_read_registers = 125; // FC 17 read part
    pub const max_rw_write_registers = 121; // FC 17 write part
};

/// Public function codes implemented by this module.
pub const FunctionCode = enum(u8) {
    read_coils = 0x01,
    read_discrete_inputs = 0x02,
    read_holding_registers = 0x03,
    read_input_registers = 0x04,
    write_single_coil = 0x05,
    write_single_register = 0x06,
    write_multiple_coils = 0x0F,
    write_multiple_registers = 0x10,
    read_write_multiple_registers = 0x17,
};

/// Modbus exception codes (application spec section 7). Non-exhaustive:
/// servers may emit codes outside the published table.
pub const ExceptionCode = enum(u8) {
    illegal_function = 0x01,
    illegal_data_address = 0x02,
    illegal_data_value = 0x03,
    server_device_failure = 0x04,
    acknowledge = 0x05,
    server_device_busy = 0x06,
    negative_acknowledge = 0x07,
    memory_parity_error = 0x08,
    gateway_path_unavailable = 0x0A,
    gateway_target_failed = 0x0B,
    _,
};

// ── error sets ──────────────────────────────────────────────────────────────

/// Request-building failures (all detected locally, before any I/O).
pub const EncodeError = error{
    /// Quantity is zero or exceeds the spec limit for the function code.
    InvalidQuantity,
    /// start address + quantity would run past the 16-bit address space.
    AddressOverflow,
    /// A PDU handed to an ADU wrapper is empty or longer than 253 bytes.
    PduTooLong,
    /// Destination buffer too small for the encoded frame.
    BufferTooSmall,
};

/// ADU-level reply validation failures.
pub const FrameError = error{
    ShortFrame,
    FrameTooLong,
    /// RTU CRC-16 check failed.
    BadCrc,
    /// MBAP protocol identifier is not 0.
    ProtocolIdMismatch,
    /// MBAP length field disagrees with the actual frame length.
    LengthMismatch,
    /// MBAP transaction id of the reply differs from the request.
    TransactionIdMismatch,
    /// Reply came from a different unit (slave address) than addressed.
    UnitMismatch,
};

/// PDU-level reply validation failures.
pub const ParseError = error{
    ShortFrame,
    /// Reply function code matches neither the request nor its exception.
    FunctionMismatch,
    /// Byte count / echoed fields inconsistent with the request.
    MalformedResponse,
};

/// A well-formed exception response (function | 0x80 + exception code),
/// mapped to one typed error per published exception code.
pub const ExceptionError = error{
    IllegalFunction, // 0x01
    IllegalDataAddress, // 0x02
    IllegalDataValue, // 0x03
    ServerDeviceFailure, // 0x04
    Acknowledge, // 0x05
    ServerDeviceBusy, // 0x06
    NegativeAcknowledge, // 0x07
    MemoryParityError, // 0x08
    GatewayPathUnavailable, // 0x0A
    GatewayTargetFailed, // 0x0B
    UnknownException, // anything else
};

/// Map a raw exception code byte to its typed error.
pub fn exceptionError(code: u8) ExceptionError {
    return switch (code) {
        0x01 => error.IllegalFunction,
        0x02 => error.IllegalDataAddress,
        0x03 => error.IllegalDataValue,
        0x04 => error.ServerDeviceFailure,
        0x05 => error.Acknowledge,
        0x06 => error.ServerDeviceBusy,
        0x07 => error.NegativeAcknowledge,
        0x08 => error.MemoryParityError,
        0x0A => error.GatewayPathUnavailable,
        0x0B => error.GatewayTargetFailed,
        else => error.UnknownException,
    };
}

/// Failures a `Transport` implementation may report.
pub const TransportError = error{ TransportFailed, Timeout };

// ── CRC-16 (Modbus) ─────────────────────────────────────────────────────────

const crc16_table: [256]u16 = blk: {
    @setEvalBranchQuota(8000);
    var table: [256]u16 = undefined;
    for (&table, 0..) |*entry, i| {
        var crc: u16 = @intCast(i);
        for (0..8) |_| {
            crc = if (crc & 1 != 0) (crc >> 1) ^ 0xA001 else crc >> 1;
        }
        entry.* = crc;
    }
    break :blk table;
};

/// CRC-16/MODBUS: poly 0x8005 reflected (0xA001), init 0xFFFF, no final
/// xor. On the RTU wire the low byte is transmitted first (little-endian).
pub fn crc16(bytes: []const u8) u16 {
    var crc: u16 = 0xFFFF;
    for (bytes) |b| crc = (crc >> 8) ^ crc16_table[@as(u8, @truncate(crc)) ^ b];
    return crc;
}

// ── coil bit packing (LSB-first, per spec sections 6.1 / 6.11) ─────────────

/// Bytes needed to carry `count` packed coil/discrete-input bits.
pub fn bitByteCount(count: usize) usize {
    return (count + 7) / 8;
}

/// Pack bools into bytes LSB-first (first coil = bit 0 of the first byte);
/// unused high bits of the last byte are zero. `dst` must hold
/// `bitByteCount(bits.len)` bytes. Returns the written prefix of `dst`.
pub fn packBits(dst: []u8, bits: []const bool) []u8 {
    const n = bitByteCount(bits.len);
    std.debug.assert(dst.len >= n);
    @memset(dst[0..n], 0);
    for (bits, 0..) |bit, i| {
        if (bit) {
            const shift: u3 = @intCast(i % 8);
            dst[i / 8] |= @as(u8, 1) << shift;
        }
    }
    return dst[0..n];
}

/// Unpack `out.len` bits from LSB-first packed bytes. `src` must hold
/// `bitByteCount(out.len)` bytes.
pub fn unpackBits(src: []const u8, out: []bool) void {
    std.debug.assert(src.len >= bitByteCount(out.len));
    for (out, 0..) |*bit, i| {
        const shift: u3 = @intCast(i % 8);
        bit.* = (src[i / 8] >> shift) & 1 != 0;
    }
}

// ── PDU codec (transport-independent) ───────────────────────────────────────

/// Request encoding + response parsing at the PDU level (function code +
/// data, no framing). All encoders write into a caller buffer and return
/// the written prefix; all parsers take the raw reply PDU.
pub const pdu = struct {
    fn checkRange(addr: u16, quantity: u16, max: u16) EncodeError!void {
        if (quantity == 0 or quantity > max) return error.InvalidQuantity;
        if (@as(u32, addr) + quantity > 0x1_0000) return error.AddressOverflow;
    }

    /// FC 01 / 02 / 03 / 04 request: start address + quantity.
    pub fn encodeReadRequest(buf: []u8, fc: FunctionCode, addr: u16, quantity: u16) EncodeError![]u8 {
        const max: u16 = switch (fc) {
            .read_coils, .read_discrete_inputs => limits.max_read_bits,
            .read_holding_registers, .read_input_registers => limits.max_read_registers,
            else => unreachable, // not a read function code
        };
        try checkRange(addr, quantity, max);
        if (buf.len < 5) return error.BufferTooSmall;
        buf[0] = @intFromEnum(fc);
        std.mem.writeInt(u16, buf[1..3], addr, .big);
        std.mem.writeInt(u16, buf[3..5], quantity, .big);
        return buf[0..5];
    }

    /// FC 05 request: output value 0xFF00 = ON, 0x0000 = OFF.
    pub fn encodeWriteSingleCoil(buf: []u8, addr: u16, on: bool) EncodeError![]u8 {
        if (buf.len < 5) return error.BufferTooSmall;
        buf[0] = @intFromEnum(FunctionCode.write_single_coil);
        std.mem.writeInt(u16, buf[1..3], addr, .big);
        std.mem.writeInt(u16, buf[3..5], if (on) 0xFF00 else 0x0000, .big);
        return buf[0..5];
    }

    /// FC 06 request.
    pub fn encodeWriteSingleRegister(buf: []u8, addr: u16, value: u16) EncodeError![]u8 {
        if (buf.len < 5) return error.BufferTooSmall;
        buf[0] = @intFromEnum(FunctionCode.write_single_register);
        std.mem.writeInt(u16, buf[1..3], addr, .big);
        std.mem.writeInt(u16, buf[3..5], value, .big);
        return buf[0..5];
    }

    /// FC 0F request: coil values packed LSB-first.
    pub fn encodeWriteMultipleCoils(buf: []u8, addr: u16, values: []const bool) EncodeError![]u8 {
        const quantity = std.math.cast(u16, values.len) orelse return error.InvalidQuantity;
        try checkRange(addr, quantity, limits.max_write_bits);
        const nbytes = bitByteCount(values.len);
        const total = 6 + nbytes;
        if (buf.len < total) return error.BufferTooSmall;
        buf[0] = @intFromEnum(FunctionCode.write_multiple_coils);
        std.mem.writeInt(u16, buf[1..3], addr, .big);
        std.mem.writeInt(u16, buf[3..5], quantity, .big);
        buf[5] = @intCast(nbytes);
        _ = packBits(buf[6..total], values);
        return buf[0..total];
    }

    /// FC 10 request: register values big-endian.
    pub fn encodeWriteMultipleRegisters(buf: []u8, addr: u16, values: []const u16) EncodeError![]u8 {
        const quantity = std.math.cast(u16, values.len) orelse return error.InvalidQuantity;
        try checkRange(addr, quantity, limits.max_write_registers);
        const total = 6 + 2 * values.len;
        if (buf.len < total) return error.BufferTooSmall;
        buf[0] = @intFromEnum(FunctionCode.write_multiple_registers);
        std.mem.writeInt(u16, buf[1..3], addr, .big);
        std.mem.writeInt(u16, buf[3..5], quantity, .big);
        buf[5] = @intCast(2 * values.len);
        for (values, 0..) |v, i| std.mem.writeInt(u16, buf[6 + 2 * i ..][0..2], v, .big);
        return buf[0..total];
    }

    /// FC 17 request: read range + registers to write (write happens first
    /// on the server, per spec).
    pub fn encodeReadWriteMultipleRegisters(
        buf: []u8,
        read_addr: u16,
        read_quantity: u16,
        write_addr: u16,
        write_values: []const u16,
    ) EncodeError![]u8 {
        const wq = std.math.cast(u16, write_values.len) orelse return error.InvalidQuantity;
        try checkRange(read_addr, read_quantity, limits.max_rw_read_registers);
        try checkRange(write_addr, wq, limits.max_rw_write_registers);
        const total = 10 + 2 * write_values.len;
        if (buf.len < total) return error.BufferTooSmall;
        buf[0] = @intFromEnum(FunctionCode.read_write_multiple_registers);
        std.mem.writeInt(u16, buf[1..3], read_addr, .big);
        std.mem.writeInt(u16, buf[3..5], read_quantity, .big);
        std.mem.writeInt(u16, buf[5..7], write_addr, .big);
        std.mem.writeInt(u16, buf[7..9], wq, .big);
        buf[9] = @intCast(2 * write_values.len);
        for (write_values, 0..) |v, i| std.mem.writeInt(u16, buf[10 + 2 * i ..][0..2], v, .big);
        return buf[0..total];
    }

    /// Validate the reply function code against the request. Returns the
    /// payload after the function-code byte, or the typed exception error
    /// for a well-formed exception response (expected | 0x80).
    pub fn checkFunction(resp: []const u8, expected: FunctionCode) (ParseError || ExceptionError)![]const u8 {
        if (resp.len == 0) return error.ShortFrame;
        const want = @intFromEnum(expected);
        if (resp[0] == want) return resp[1..];
        if (resp[0] == want | 0x80) {
            if (resp.len < 2) return error.ShortFrame;
            return exceptionError(resp[1]);
        }
        return error.FunctionMismatch;
    }

    /// FC 01 / 02 response: byte count + packed bits into `out.len` bools.
    pub fn parseReadBitsResponse(
        resp: []const u8,
        expected: FunctionCode,
        out: []bool,
    ) (ParseError || ExceptionError)!void {
        const payload = try checkFunction(resp, expected);
        if (payload.len < 1) return error.ShortFrame;
        const nbytes = bitByteCount(out.len);
        if (payload[0] != nbytes or payload.len != 1 + nbytes) return error.MalformedResponse;
        unpackBits(payload[1..], out);
    }

    /// FC 03 / 04 / 17 response: byte count + big-endian registers into
    /// `out.len` values.
    pub fn parseReadRegistersResponse(
        resp: []const u8,
        expected: FunctionCode,
        out: []u16,
    ) (ParseError || ExceptionError)!void {
        const payload = try checkFunction(resp, expected);
        if (payload.len < 1) return error.ShortFrame;
        const nbytes = 2 * out.len;
        if (payload[0] != nbytes or payload.len != 1 + nbytes) return error.MalformedResponse;
        for (out, 0..) |*reg, i| reg.* = std.mem.readInt(u16, payload[1 + 2 * i ..][0..2], .big);
    }

    /// FC 05 / 06 response: exact echo of address + value.
    pub fn parseWriteSingleResponse(
        resp: []const u8,
        expected: FunctionCode,
        addr: u16,
        value: u16,
    ) (ParseError || ExceptionError)!void {
        const payload = try checkFunction(resp, expected);
        if (payload.len != 4) return error.MalformedResponse;
        if (std.mem.readInt(u16, payload[0..2], .big) != addr) return error.MalformedResponse;
        if (std.mem.readInt(u16, payload[2..4], .big) != value) return error.MalformedResponse;
    }

    /// FC 0F / 10 response: echo of start address + quantity.
    pub fn parseWriteMultipleResponse(
        resp: []const u8,
        expected: FunctionCode,
        addr: u16,
        quantity: u16,
    ) (ParseError || ExceptionError)!void {
        const payload = try checkFunction(resp, expected);
        if (payload.len != 4) return error.MalformedResponse;
        if (std.mem.readInt(u16, payload[0..2], .big) != addr) return error.MalformedResponse;
        if (std.mem.readInt(u16, payload[2..4], .big) != quantity) return error.MalformedResponse;
    }
};

// ── TCP framing (MBAP) ──────────────────────────────────────────────────────

/// Modbus TCP ADU: MBAP header (transaction id, protocol id 0, length,
/// unit id) followed by the PDU.
pub const tcp = struct {
    pub const header_len = 7;
    pub const max_adu_len = header_len + max_pdu_len; // 260
    pub const protocol_id = 0;

    pub const Frame = struct {
        transaction_id: u16,
        unit: u8,
        pdu: []const u8,
    };

    pub fn encodeAdu(buf: []u8, transaction_id: u16, unit: u8, pdu_bytes: []const u8) EncodeError![]u8 {
        if (pdu_bytes.len == 0 or pdu_bytes.len > max_pdu_len) return error.PduTooLong;
        const total = header_len + pdu_bytes.len;
        if (buf.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u16, buf[0..2], transaction_id, .big);
        std.mem.writeInt(u16, buf[2..4], protocol_id, .big);
        std.mem.writeInt(u16, buf[4..6], @intCast(1 + pdu_bytes.len), .big); // unit + PDU
        buf[6] = unit;
        @memcpy(buf[header_len..total], pdu_bytes);
        return buf[0..total];
    }

    pub fn decodeAdu(frame: []const u8) FrameError!Frame {
        if (frame.len < header_len + 1) return error.ShortFrame; // header + function code
        if (frame.len > max_adu_len) return error.FrameTooLong;
        if (std.mem.readInt(u16, frame[2..4], .big) != protocol_id) return error.ProtocolIdMismatch;
        const len_field = std.mem.readInt(u16, frame[4..6], .big);
        if (@as(usize, len_field) + 6 != frame.len) return error.LengthMismatch;
        return .{
            .transaction_id = std.mem.readInt(u16, frame[0..2], .big),
            .unit = frame[6],
            .pdu = frame[header_len..],
        };
    }
};

// ── RTU framing (address + PDU + CRC-16) ────────────────────────────────────

/// Modbus RTU ADU: slave address + PDU + CRC-16 (low byte first). Inter-
/// frame silent intervals (t3.5) are the transport's concern, not encoded
/// here.
pub const rtu = struct {
    pub const max_adu_len = 1 + max_pdu_len + 2; // 256

    pub const Frame = struct {
        unit: u8,
        pdu: []const u8,
    };

    pub fn encodeAdu(buf: []u8, unit: u8, pdu_bytes: []const u8) EncodeError![]u8 {
        if (pdu_bytes.len == 0 or pdu_bytes.len > max_pdu_len) return error.PduTooLong;
        const total = 1 + pdu_bytes.len + 2;
        if (buf.len < total) return error.BufferTooSmall;
        buf[0] = unit;
        @memcpy(buf[1 .. 1 + pdu_bytes.len], pdu_bytes);
        const crc = crc16(buf[0 .. 1 + pdu_bytes.len]);
        std.mem.writeInt(u16, buf[1 + pdu_bytes.len ..][0..2], crc, .little);
        return buf[0..total];
    }

    pub fn decodeAdu(frame: []const u8) FrameError!Frame {
        if (frame.len < 4) return error.ShortFrame; // addr + fc + crc
        if (frame.len > max_adu_len) return error.FrameTooLong;
        const body = frame[0 .. frame.len - 2];
        const wire_crc = std.mem.readInt(u16, frame[frame.len - 2 ..][0..2], .little);
        if (crc16(body) != wire_crc) return error.BadCrc;
        return .{ .unit = frame[0], .pdu = body[1..] };
    }
};

// ── transport seam ──────────────────────────────────────────────────────────

/// The I/O seam: one blocking round-trip — send a request ADU, receive one
/// reply ADU into `reply_buf`, return its length. Implementations own all
/// framing-boundary concerns (MBAP length prefix on TCP, t3.5 silence on
/// serial). Tests drive the client from fixed buffers through this seam.
pub const Transport = struct {
    ctx: *anyopaque,
    exchangeFn: *const fn (ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize,

    pub fn exchange(t: Transport, request: []const u8, reply_buf: []u8) TransportError![]const u8 {
        const n = try t.exchangeFn(t.ctx, request, reply_buf);
        if (n > reply_buf.len) return error.TransportFailed;
        return reply_buf[0..n];
    }
};

pub const Framing = enum { tcp, rtu };

// ── client (master) ─────────────────────────────────────────────────────────

/// Modbus master. Framing (TCP or RTU) is chosen at init; all I/O goes
/// through the `Transport` seam. Allocation-free: results land in caller
/// slices whose length is the requested quantity. Not thread-safe (the TCP
/// transaction id is client state) — one owner at a time.
pub const Client = struct {
    transport: Transport,
    framing: Framing,
    next_transaction_id: u16 = 1,

    pub const Error = EncodeError || FrameError || ParseError || ExceptionError || TransportError;

    pub fn init(framing: Framing, transport: Transport) Client {
        return .{ .transport = transport, .framing = framing };
    }

    /// FC 01: read `out.len` coils starting at `addr`.
    pub fn readCoils(c: *Client, unit: u8, addr: u16, out: []bool) Error!void {
        try c.readBits(.read_coils, unit, addr, out);
    }

    /// FC 02: read `out.len` discrete inputs starting at `addr`.
    pub fn readDiscreteInputs(c: *Client, unit: u8, addr: u16, out: []bool) Error!void {
        try c.readBits(.read_discrete_inputs, unit, addr, out);
    }

    /// FC 03: read `out.len` holding registers starting at `addr`.
    pub fn readHoldingRegisters(c: *Client, unit: u8, addr: u16, out: []u16) Error!void {
        try c.readRegisters(.read_holding_registers, unit, addr, out);
    }

    /// FC 04: read `out.len` input registers starting at `addr`.
    pub fn readInputRegisters(c: *Client, unit: u8, addr: u16, out: []u16) Error!void {
        try c.readRegisters(.read_input_registers, unit, addr, out);
    }

    /// FC 05: write one coil.
    pub fn writeSingleCoil(c: *Client, unit: u8, addr: u16, on: bool) Error!void {
        var req_buf: [5]u8 = undefined;
        const req = try pdu.encodeWriteSingleCoil(&req_buf, addr, on);
        var reply_buf: [tcp.max_adu_len]u8 = undefined;
        const resp = try c.exchangePdu(unit, req, &reply_buf);
        try pdu.parseWriteSingleResponse(resp, .write_single_coil, addr, if (on) 0xFF00 else 0x0000);
    }

    /// FC 06: write one holding register.
    pub fn writeSingleRegister(c: *Client, unit: u8, addr: u16, value: u16) Error!void {
        var req_buf: [5]u8 = undefined;
        const req = try pdu.encodeWriteSingleRegister(&req_buf, addr, value);
        var reply_buf: [tcp.max_adu_len]u8 = undefined;
        const resp = try c.exchangePdu(unit, req, &reply_buf);
        try pdu.parseWriteSingleResponse(resp, .write_single_register, addr, value);
    }

    /// FC 0F: write `values.len` coils starting at `addr`.
    pub fn writeMultipleCoils(c: *Client, unit: u8, addr: u16, values: []const bool) Error!void {
        var req_buf: [max_pdu_len]u8 = undefined;
        const req = try pdu.encodeWriteMultipleCoils(&req_buf, addr, values);
        var reply_buf: [tcp.max_adu_len]u8 = undefined;
        const resp = try c.exchangePdu(unit, req, &reply_buf);
        try pdu.parseWriteMultipleResponse(resp, .write_multiple_coils, addr, @intCast(values.len));
    }

    /// FC 10: write `values.len` holding registers starting at `addr`.
    pub fn writeMultipleRegisters(c: *Client, unit: u8, addr: u16, values: []const u16) Error!void {
        var req_buf: [max_pdu_len]u8 = undefined;
        const req = try pdu.encodeWriteMultipleRegisters(&req_buf, addr, values);
        var reply_buf: [tcp.max_adu_len]u8 = undefined;
        const resp = try c.exchangePdu(unit, req, &reply_buf);
        try pdu.parseWriteMultipleResponse(resp, .write_multiple_registers, addr, @intCast(values.len));
    }

    /// FC 17: write `values.len` registers at `write_addr`, then read
    /// `out.len` registers from `read_addr`, in one transaction.
    pub fn readWriteMultipleRegisters(
        c: *Client,
        unit: u8,
        read_addr: u16,
        out: []u16,
        write_addr: u16,
        values: []const u16,
    ) Error!void {
        const rq = std.math.cast(u16, out.len) orelse return error.InvalidQuantity;
        var req_buf: [max_pdu_len]u8 = undefined;
        const req = try pdu.encodeReadWriteMultipleRegisters(&req_buf, read_addr, rq, write_addr, values);
        var reply_buf: [tcp.max_adu_len]u8 = undefined;
        const resp = try c.exchangePdu(unit, req, &reply_buf);
        try pdu.parseReadRegistersResponse(resp, .read_write_multiple_registers, out);
    }

    fn readBits(c: *Client, fc: FunctionCode, unit: u8, addr: u16, out: []bool) Error!void {
        const quantity = std.math.cast(u16, out.len) orelse return error.InvalidQuantity;
        var req_buf: [5]u8 = undefined;
        const req = try pdu.encodeReadRequest(&req_buf, fc, addr, quantity);
        var reply_buf: [tcp.max_adu_len]u8 = undefined;
        const resp = try c.exchangePdu(unit, req, &reply_buf);
        try pdu.parseReadBitsResponse(resp, fc, out);
    }

    fn readRegisters(c: *Client, fc: FunctionCode, unit: u8, addr: u16, out: []u16) Error!void {
        const quantity = std.math.cast(u16, out.len) orelse return error.InvalidQuantity;
        var req_buf: [5]u8 = undefined;
        const req = try pdu.encodeReadRequest(&req_buf, fc, addr, quantity);
        var reply_buf: [tcp.max_adu_len]u8 = undefined;
        const resp = try c.exchangePdu(unit, req, &reply_buf);
        try pdu.parseReadRegistersResponse(resp, fc, out);
    }

    /// Wrap the request PDU in the configured framing, run one transport
    /// round-trip, unwrap + validate the reply ADU, return the reply PDU
    /// (a slice into `reply_buf`).
    fn exchangePdu(c: *Client, unit: u8, request_pdu: []const u8, reply_buf: *[tcp.max_adu_len]u8) Error![]const u8 {
        var adu_buf: [tcp.max_adu_len]u8 = undefined;
        switch (c.framing) {
            .tcp => {
                const txid = c.next_transaction_id;
                c.next_transaction_id +%= 1;
                const adu = try tcp.encodeAdu(&adu_buf, txid, unit, request_pdu);
                const reply = try c.transport.exchange(adu, reply_buf);
                const frame = try tcp.decodeAdu(reply);
                if (frame.transaction_id != txid) return error.TransactionIdMismatch;
                if (frame.unit != unit) return error.UnitMismatch;
                return frame.pdu;
            },
            .rtu => {
                const adu = try rtu.encodeAdu(&adu_buf, unit, request_pdu);
                const reply = try c.transport.exchange(adu, reply_buf);
                const frame = try rtu.decodeAdu(reply);
                if (frame.unit != unit) return error.UnitMismatch;
                return frame.pdu;
            },
        }
    }
};

// ── optional real transport: Modbus TCP over std.Io.net ────────────────────
// Demo convenience only — nothing in the codec, client, or tests needs it.

/// Blocking Modbus TCP transport over `std.Io.net`. TCP framing only (it
/// reads the MBAP length field to delimit the reply).
pub const TcpTransport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,

    /// Standard Modbus TCP port.
    pub const default_port = 502;

    pub fn connect(io: std.Io, address: std.Io.net.IpAddress) !TcpTransport {
        const stream = try address.connect(io, .{ .mode = .stream });
        return .{ .io = io, .stream = stream };
    }

    pub fn close(t: *TcpTransport) void {
        t.stream.close(t.io);
    }

    pub fn transport(t: *TcpTransport) Transport {
        return .{ .ctx = t, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize {
        const t: *TcpTransport = @ptrCast(@alignCast(ctx));

        var wbuf: [tcp.max_adu_len]u8 = undefined;
        var sw = t.stream.writer(t.io, &wbuf);
        sw.interface.writeAll(request) catch return error.TransportFailed;
        sw.interface.flush() catch return error.TransportFailed;

        // Strict request/reply: read the 7-byte MBAP header, then exactly
        // the bytes its length field announces.
        var rbuf: [tcp.max_adu_len]u8 = undefined;
        var sr = t.stream.reader(t.io, &rbuf);
        const r = &sr.interface;
        if (reply_buf.len < tcp.header_len) return error.TransportFailed;
        r.readSliceAll(reply_buf[0..tcp.header_len]) catch return error.TransportFailed;
        const len_field: usize = std.mem.readInt(u16, reply_buf[4..6], .big);
        const total = 6 + len_field;
        if (len_field < 1 or total > reply_buf.len) return error.TransportFailed;
        r.readSliceAll(reply_buf[tcp.header_len..total]) catch return error.TransportFailed;
        return total;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// A scripted transport: records the request ADU, replies from a fixed
// buffer. Lets every client test run offline from spec wire examples.
const MockTransport = struct {
    reply: []const u8,
    got: [tcp.max_adu_len]u8 = undefined,
    got_len: usize = 0,

    fn transport(m: *MockTransport) Transport {
        return .{ .ctx = m, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize {
        const m: *MockTransport = @ptrCast(@alignCast(ctx));
        if (request.len > m.got.len) return error.TransportFailed;
        @memcpy(m.got[0..request.len], request);
        m.got_len = request.len;
        if (m.reply.len > reply_buf.len) return error.TransportFailed;
        @memcpy(reply_buf[0..m.reply.len], m.reply);
        return m.reply.len;
    }

    fn gotBytes(m: *const MockTransport) []const u8 {
        return m.got[0..m.got_len];
    }
};

test "CRC-16/MODBUS canonical check value" {
    // CRC catalog check value: CRC-16/MODBUS("123456789") = 0x4B37.
    try testing.expectEqual(@as(u16, 0x4B37), crc16("123456789"));
}

test "CRC-16 known frames and wire byte order" {
    // Classic example frame: 01 03 00 00 00 0A -> CRC 0xCDC5, wire C5 CD.
    try testing.expectEqual(@as(u16, 0xCDC5), crc16(&.{ 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A }));
    try testing.expectEqual(@as(u16, 0x80B8), crc16(&.{ 0x01, 0x04, 0x02, 0xFF, 0xFF }));

    var buf: [16]u8 = undefined;
    const adu = try rtu.encodeAdu(&buf, 0x01, &.{ 0x03, 0x00, 0x00, 0x00, 0x0A });
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD }, adu);
}

test "bit packing round trip, LSB-first" {
    const bits = [_]bool{ true, false, true, true, false, false, true, true, true, false };
    var packed_buf: [2]u8 = undefined;
    const bytes = packBits(&packed_buf, &bits);
    try testing.expectEqualSlices(u8, &.{ 0xCD, 0x01 }, bytes);
    var back: [bits.len]bool = undefined;
    unpackBits(bytes, &back);
    try testing.expectEqualSlices(bool, &bits, &back);
}

test "spec KAT: FC 01 read coils 20-38" {
    var buf: [8]u8 = undefined;
    const req = try pdu.encodeReadRequest(&buf, .read_coils, 0x0013, 0x0013);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x13, 0x00, 0x13 }, req);

    var out: [19]bool = undefined;
    try pdu.parseReadBitsResponse(&.{ 0x01, 0x03, 0xCD, 0x6B, 0x05 }, .read_coils, &out);
    const expected = [19]bool{
        true, false, true, true, false, false, true, true, // 0xCD: coils 20..27
        true, true, false, true, false, true, true, false, // 0x6B: coils 28..35
        true, false, true, // 0x05: coils 36..38
    };
    try testing.expectEqualSlices(bool, &expected, &out);
}

test "spec KAT: FC 02 read discrete inputs 197-218" {
    var buf: [8]u8 = undefined;
    const req = try pdu.encodeReadRequest(&buf, .read_discrete_inputs, 0x00C4, 0x0016);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x00, 0xC4, 0x00, 0x16 }, req);

    var out: [22]bool = undefined;
    try pdu.parseReadBitsResponse(&.{ 0x02, 0x03, 0xAC, 0xDB, 0x35 }, .read_discrete_inputs, &out);
    const expected = [22]bool{
        false, false, true, true, false, true, false, true, // 0xAC
        true, true, false, true, true, false, true, true, // 0xDB
        true, false, true, false, true, true, // 0x35 (6 bits)
    };
    try testing.expectEqualSlices(bool, &expected, &out);
}

test "spec KAT: FC 03 read holding registers 108-110" {
    var buf: [8]u8 = undefined;
    const req = try pdu.encodeReadRequest(&buf, .read_holding_registers, 0x006B, 0x0003);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x00, 0x6B, 0x00, 0x03 }, req);

    var out: [3]u16 = undefined;
    try pdu.parseReadRegistersResponse(
        &.{ 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64 },
        .read_holding_registers,
        &out,
    );
    try testing.expectEqualSlices(u16, &.{ 555, 0, 100 }, &out);
}

test "spec KAT: FC 04 read input register 9" {
    var buf: [8]u8 = undefined;
    const req = try pdu.encodeReadRequest(&buf, .read_input_registers, 0x0008, 0x0001);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x00, 0x08, 0x00, 0x01 }, req);

    var out: [1]u16 = undefined;
    try pdu.parseReadRegistersResponse(&.{ 0x04, 0x02, 0x00, 0x0A }, .read_input_registers, &out);
    try testing.expectEqual(@as(u16, 10), out[0]);
}

test "spec KAT: FC 05 write single coil 173 on" {
    var buf: [8]u8 = undefined;
    const req = try pdu.encodeWriteSingleCoil(&buf, 0x00AC, true);
    try testing.expectEqualSlices(u8, &.{ 0x05, 0x00, 0xAC, 0xFF, 0x00 }, req);
    // Response is an echo of the request.
    try pdu.parseWriteSingleResponse(&.{ 0x05, 0x00, 0xAC, 0xFF, 0x00 }, .write_single_coil, 0x00AC, 0xFF00);

    const off = try pdu.encodeWriteSingleCoil(&buf, 0x00AC, false);
    try testing.expectEqualSlices(u8, &.{ 0x05, 0x00, 0xAC, 0x00, 0x00 }, off);
}

test "spec KAT: FC 06 write single register 2 = 3" {
    var buf: [8]u8 = undefined;
    const req = try pdu.encodeWriteSingleRegister(&buf, 0x0001, 0x0003);
    try testing.expectEqualSlices(u8, &.{ 0x06, 0x00, 0x01, 0x00, 0x03 }, req);
    try pdu.parseWriteSingleResponse(&.{ 0x06, 0x00, 0x01, 0x00, 0x03 }, .write_single_register, 0x0001, 0x0003);
}

test "spec KAT: FC 0F write 10 coils from coil 20" {
    const values = [_]bool{ true, false, true, true, false, false, true, true, true, false };
    var buf: [16]u8 = undefined;
    const req = try pdu.encodeWriteMultipleCoils(&buf, 0x0013, &values);
    try testing.expectEqualSlices(u8, &.{ 0x0F, 0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01 }, req);
    try pdu.parseWriteMultipleResponse(&.{ 0x0F, 0x00, 0x13, 0x00, 0x0A }, .write_multiple_coils, 0x0013, 10);
}

test "spec KAT: FC 10 write 2 registers from register 2" {
    var buf: [16]u8 = undefined;
    const req = try pdu.encodeWriteMultipleRegisters(&buf, 0x0001, &.{ 0x000A, 0x0102 });
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02 }, req);
    try pdu.parseWriteMultipleResponse(&.{ 0x10, 0x00, 0x01, 0x00, 0x02 }, .write_multiple_registers, 0x0001, 2);
}

test "spec KAT: FC 17 read six registers, write three" {
    var buf: [32]u8 = undefined;
    const req = try pdu.encodeReadWriteMultipleRegisters(&buf, 0x0003, 6, 0x000E, &.{ 0x00FF, 0x00FF, 0x00FF });
    try testing.expectEqualSlices(u8, &.{
        0x17, 0x00, 0x03, 0x00, 0x06, 0x00, 0x0E, 0x00,
        0x03, 0x06, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
    }, req);

    var out: [6]u16 = undefined;
    try pdu.parseReadRegistersResponse(&.{
        0x17, 0x0C, 0x00, 0xFE, 0x0A, 0xCD, 0x00, 0x01,
        0x00, 0x03, 0x00, 0x0D, 0x00, 0xFF,
    }, .read_write_multiple_registers, &out);
    try testing.expectEqualSlices(u16, &.{ 0x00FE, 0x0ACD, 0x0001, 0x0003, 0x000D, 0x00FF }, &out);
}

test "TCP ADU encode + decode round trip" {
    var buf: [tcp.max_adu_len]u8 = undefined;
    const adu = try tcp.encodeAdu(&buf, 0x1234, 0x11, &.{ 0x03, 0x00, 0x6B, 0x00, 0x03 });
    try testing.expectEqualSlices(u8, &.{
        0x12, 0x34, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x03,
    }, adu);

    const frame = try tcp.decodeAdu(adu);
    try testing.expectEqual(@as(u16, 0x1234), frame.transaction_id);
    try testing.expectEqual(@as(u8, 0x11), frame.unit);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x00, 0x6B, 0x00, 0x03 }, frame.pdu);
}

test "RTU ADU encode KAT + decode round trip" {
    var buf: [rtu.max_adu_len]u8 = undefined;
    // Spec FC 03 example as an RTU frame for unit 1; CRC verified against
    // two independent implementations: 0x1774 -> wire 74 17.
    const adu = try rtu.encodeAdu(&buf, 0x01, &.{ 0x03, 0x00, 0x6B, 0x00, 0x03 });
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x74, 0x17 }, adu);

    const frame = try rtu.decodeAdu(adu);
    try testing.expectEqual(@as(u8, 0x01), frame.unit);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x00, 0x6B, 0x00, 0x03 }, frame.pdu);

    // Matching response frame: CRC 0x7A05 -> wire 05 7A.
    const resp = try rtu.decodeAdu(&.{ 0x01, 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64, 0x05, 0x7A });
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64 }, resp.pdu);
}

test "client TCP round trip: read holding registers" {
    var mock = MockTransport{ .reply = &.{
        0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x11, 0x03,
        0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64,
    } };
    var client = Client.init(.tcp, mock.transport());
    var regs: [3]u16 = undefined;
    try client.readHoldingRegisters(0x11, 0x006B, &regs);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x03,
    }, mock.gotBytes());
    try testing.expectEqualSlices(u16, &.{ 555, 0, 100 }, &regs);
    try testing.expectEqual(@as(u16, 2), client.next_transaction_id);
}

test "client TCP round trip: read coils" {
    var mock = MockTransport{ .reply = &.{
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x01, 0x03, 0xCD, 0x6B, 0x05,
    } };
    var client = Client.init(.tcp, mock.transport());
    var coils: [19]bool = undefined;
    try client.readCoils(0x11, 0x0013, &coils);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x01, 0x00, 0x13, 0x00, 0x13,
    }, mock.gotBytes());
    try testing.expect(coils[0] and !coils[1] and coils[18]);
}

test "client RTU round trip: read holding registers" {
    var mock = MockTransport{ .reply = &.{
        0x01, 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64, 0x05, 0x7A,
    } };
    var client = Client.init(.rtu, mock.transport());
    var regs: [3]u16 = undefined;
    try client.readHoldingRegisters(0x01, 0x006B, &regs);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x74, 0x17 }, mock.gotBytes());
    try testing.expectEqualSlices(u16, &.{ 555, 0, 100 }, &regs);
}

test "client RTU round trip: writes with echoed replies" {
    // Reply frames are built with our own encoder (round trip); the byte-
    // level encode correctness is covered by the KATs above.
    var reply_buf: [rtu.max_adu_len]u8 = undefined;

    var mock = MockTransport{
        .reply = try rtu.encodeAdu(&reply_buf, 0x11, &.{ 0x06, 0x00, 0x01, 0x00, 0x03 }),
    };
    var client = Client.init(.rtu, mock.transport());
    try client.writeSingleRegister(0x11, 0x0001, 0x0003);

    var reply_buf2: [rtu.max_adu_len]u8 = undefined;
    var mock2 = MockTransport{
        .reply = try rtu.encodeAdu(&reply_buf2, 0x11, &.{ 0x10, 0x00, 0x01, 0x00, 0x02 }),
    };
    var client2 = Client.init(.rtu, mock2.transport());
    try client2.writeMultipleRegisters(0x11, 0x0001, &.{ 0x000A, 0x0102 });
    try testing.expectEqualSlices(
        u8,
        &.{ 0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02 },
        (try rtu.decodeAdu(mock2.gotBytes())).pdu,
    );

    var reply_buf3: [rtu.max_adu_len]u8 = undefined;
    var mock3 = MockTransport{
        .reply = try rtu.encodeAdu(&reply_buf3, 0x11, &.{ 0x0F, 0x00, 0x13, 0x00, 0x0A }),
    };
    var client3 = Client.init(.rtu, mock3.transport());
    const coil_values = [_]bool{ true, false, true, true, false, false, true, true, true, false };
    try client3.writeMultipleCoils(0x11, 0x0013, &coil_values);
}

test "client TCP round trip: read/write multiple registers" {
    var mock = MockTransport{ .reply = &.{
        0x00, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x11, 0x17,
        0x0C, 0x00, 0xFE, 0x0A, 0xCD, 0x00, 0x01, 0x00,
        0x03, 0x00, 0x0D, 0x00, 0xFF,
    } };
    var client = Client.init(.tcp, mock.transport());
    var out: [6]u16 = undefined;
    try client.readWriteMultipleRegisters(0x11, 0x0003, &out, 0x000E, &.{ 0x00FF, 0x00FF, 0x00FF });
    try testing.expectEqualSlices(u16, &.{ 0x00FE, 0x0ACD, 0x0001, 0x0003, 0x000D, 0x00FF }, &out);
}

test "exception response 0x83/0x02 -> IllegalDataAddress" {
    var mock = MockTransport{ .reply = &.{
        0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x11, 0x83, 0x02,
    } };
    var client = Client.init(.tcp, mock.transport());
    var regs: [3]u16 = undefined;
    try testing.expectError(error.IllegalDataAddress, client.readHoldingRegisters(0x11, 0x006B, &regs));
}

test "exception code mapping covers the published table" {
    try testing.expectError(error.IllegalFunction, pdu.checkFunction(&.{ 0x81, 0x01 }, .read_coils));
    try testing.expectError(error.IllegalDataAddress, pdu.checkFunction(&.{ 0x81, 0x02 }, .read_coils));
    try testing.expectError(error.IllegalDataValue, pdu.checkFunction(&.{ 0x81, 0x03 }, .read_coils));
    try testing.expectError(error.ServerDeviceFailure, pdu.checkFunction(&.{ 0x81, 0x04 }, .read_coils));
    try testing.expectError(error.Acknowledge, pdu.checkFunction(&.{ 0x81, 0x05 }, .read_coils));
    try testing.expectError(error.ServerDeviceBusy, pdu.checkFunction(&.{ 0x81, 0x06 }, .read_coils));
    try testing.expectError(error.NegativeAcknowledge, pdu.checkFunction(&.{ 0x81, 0x07 }, .read_coils));
    try testing.expectError(error.MemoryParityError, pdu.checkFunction(&.{ 0x81, 0x08 }, .read_coils));
    try testing.expectError(error.GatewayPathUnavailable, pdu.checkFunction(&.{ 0x81, 0x0A }, .read_coils));
    try testing.expectError(error.GatewayTargetFailed, pdu.checkFunction(&.{ 0x81, 0x0B }, .read_coils));
    try testing.expectError(error.UnknownException, pdu.checkFunction(&.{ 0x81, 0x63 }, .read_coils));
    // Truncated exception frame: high bit set but no exception code byte.
    try testing.expectError(error.ShortFrame, pdu.checkFunction(&.{0x81}, .read_coils));
}

test "quantity limits -> typed errors" {
    var buf: [max_pdu_len]u8 = undefined;
    try testing.expectError(error.InvalidQuantity, pdu.encodeReadRequest(&buf, .read_coils, 0, 2001));
    try testing.expectError(error.InvalidQuantity, pdu.encodeReadRequest(&buf, .read_coils, 0, 0));
    try testing.expectError(error.InvalidQuantity, pdu.encodeReadRequest(&buf, .read_holding_registers, 0, 126));
    try testing.expectError(error.InvalidQuantity, pdu.encodeReadRequest(&buf, .read_input_registers, 0, 126));
    _ = try pdu.encodeReadRequest(&buf, .read_coils, 0, 2000);
    _ = try pdu.encodeReadRequest(&buf, .read_holding_registers, 0, 125);

    const coils_ok = [_]bool{false} ** 1968;
    _ = try pdu.encodeWriteMultipleCoils(&buf, 0, &coils_ok);
    const coils_bad = [_]bool{false} ** 1969;
    try testing.expectError(error.InvalidQuantity, pdu.encodeWriteMultipleCoils(&buf, 0, &coils_bad));

    const regs_ok = [_]u16{0} ** 123;
    _ = try pdu.encodeWriteMultipleRegisters(&buf, 0, &regs_ok);
    const regs_bad = [_]u16{0} ** 124;
    try testing.expectError(error.InvalidQuantity, pdu.encodeWriteMultipleRegisters(&buf, 0, &regs_bad));

    const rw_bad = [_]u16{0} ** 122;
    try testing.expectError(error.InvalidQuantity, pdu.encodeReadWriteMultipleRegisters(&buf, 0, 1, 0, &rw_bad));
    try testing.expectError(error.InvalidQuantity, pdu.encodeReadWriteMultipleRegisters(&buf, 0, 126, 0, &.{0}));
}

test "address + quantity overflow -> AddressOverflow" {
    var buf: [8]u8 = undefined;
    try testing.expectError(error.AddressOverflow, pdu.encodeReadRequest(&buf, .read_holding_registers, 0xFFFF, 2));
    _ = try pdu.encodeReadRequest(&buf, .read_holding_registers, 0xFFFF, 1);
}

test "encode buffer too small -> BufferTooSmall" {
    var tiny: [3]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, pdu.encodeReadRequest(&tiny, .read_coils, 0, 1));
    try testing.expectError(error.BufferTooSmall, tcp.encodeAdu(&tiny, 1, 1, &.{ 0x03, 0x00 }));
    try testing.expectError(error.BufferTooSmall, rtu.encodeAdu(&tiny, 1, &.{ 0x03, 0x00 }));
    var big: [300]u8 = undefined;
    const oversized = [_]u8{0} ** (max_pdu_len + 1);
    try testing.expectError(error.PduTooLong, tcp.encodeAdu(&big, 1, 1, &oversized));
    try testing.expectError(error.PduTooLong, rtu.encodeAdu(&big, 1, &oversized));
}

test "RTU CRC corruption -> BadCrc" {
    var buf: [rtu.max_adu_len]u8 = undefined;
    const adu = try rtu.encodeAdu(&buf, 0x01, &.{ 0x03, 0x00, 0x6B, 0x00, 0x03 });
    var corrupt: [8]u8 = undefined;
    @memcpy(&corrupt, adu[0..8]);
    corrupt[3] ^= 0x40; // flip a payload bit
    try testing.expectError(error.BadCrc, rtu.decodeAdu(&corrupt));
    corrupt[3] ^= 0x40;
    corrupt[7] ^= 0x01; // flip a CRC bit
    try testing.expectError(error.BadCrc, rtu.decodeAdu(&corrupt));

    var mock = MockTransport{ .reply = &.{ 0x01, 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64, 0x05, 0x7B } };
    var client = Client.init(.rtu, mock.transport());
    var regs: [3]u16 = undefined;
    try testing.expectError(error.BadCrc, client.readHoldingRegisters(0x01, 0x006B, &regs));
}

test "MBAP validation: txid, length, protocol id, unit" {
    var regs: [3]u16 = undefined;

    // Wrong transaction id (client sends txid 1, server echoes 2).
    var mock = MockTransport{ .reply = &.{
        0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x11, 0x03,
        0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64,
    } };
    var client = Client.init(.tcp, mock.transport());
    try testing.expectError(error.TransactionIdMismatch, client.readHoldingRegisters(0x11, 0x006B, &regs));

    // Length field disagrees with the actual frame length.
    var mock2 = MockTransport{ .reply = &.{
        0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x11, 0x03,
        0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64,
    } };
    var client2 = Client.init(.tcp, mock2.transport());
    try testing.expectError(error.LengthMismatch, client2.readHoldingRegisters(0x11, 0x006B, &regs));

    // Nonzero protocol id.
    var mock3 = MockTransport{ .reply = &.{
        0x00, 0x01, 0x00, 0x01, 0x00, 0x09, 0x11, 0x03,
        0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64,
    } };
    var client3 = Client.init(.tcp, mock3.transport());
    try testing.expectError(error.ProtocolIdMismatch, client3.readHoldingRegisters(0x11, 0x006B, &regs));

    // Reply from the wrong unit.
    var mock4 = MockTransport{ .reply = &.{
        0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x12, 0x03,
        0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64,
    } };
    var client4 = Client.init(.tcp, mock4.transport());
    try testing.expectError(error.UnitMismatch, client4.readHoldingRegisters(0x11, 0x006B, &regs));
}

test "RTU unit mismatch" {
    // A correctly CRCed reply from unit 2 to a request addressed to unit 1.
    var reply_buf: [rtu.max_adu_len]u8 = undefined;
    var mock = MockTransport{
        .reply = try rtu.encodeAdu(&reply_buf, 0x02, &.{ 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64 }),
    };
    var client = Client.init(.rtu, mock.transport());
    var regs: [3]u16 = undefined;
    try testing.expectError(error.UnitMismatch, client.readHoldingRegisters(0x01, 0x006B, &regs));
}

test "function code mismatch" {
    var mock = MockTransport{ .reply = &.{
        0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x11, 0x04, 0x02, 0x00, 0x0A,
    } };
    var client = Client.init(.tcp, mock.transport());
    var regs: [1]u16 = undefined;
    try testing.expectError(error.FunctionMismatch, client.readHoldingRegisters(0x11, 0x0008, &regs));
}

test "short and truncated frames -> ShortFrame, never panic" {
    try testing.expectError(error.ShortFrame, tcp.decodeAdu(&.{}));
    try testing.expectError(error.ShortFrame, tcp.decodeAdu(&.{ 0x00, 0x01, 0x00 }));
    try testing.expectError(error.ShortFrame, tcp.decodeAdu(&.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x11 }));
    try testing.expectError(error.ShortFrame, rtu.decodeAdu(&.{}));
    try testing.expectError(error.ShortFrame, rtu.decodeAdu(&.{ 0x01, 0x03, 0x74 }));

    var out: [4]u16 = undefined;
    try testing.expectError(error.ShortFrame, pdu.parseReadRegistersResponse(&.{}, .read_holding_registers, &out));
    try testing.expectError(error.ShortFrame, pdu.parseReadRegistersResponse(&.{0x03}, .read_holding_registers, &out));
    var bits: [4]bool = undefined;
    try testing.expectError(error.ShortFrame, pdu.parseReadBitsResponse(&.{0x01}, .read_coils, &bits));

    const too_long = [_]u8{0} ** 300;
    try testing.expectError(error.FrameTooLong, tcp.decodeAdu(&too_long));
    try testing.expectError(error.FrameTooLong, rtu.decodeAdu(&too_long));
}

test "malformed byte counts and echoes -> MalformedResponse" {
    var regs: [3]u16 = undefined;
    // Byte count says 4 but we asked for 3 registers (6 bytes).
    try testing.expectError(error.MalformedResponse, pdu.parseReadRegistersResponse(
        &.{ 0x03, 0x04, 0x02, 0x2B, 0x00, 0x00 },
        .read_holding_registers,
        &regs,
    ));
    // Byte count consistent with itself but not with the payload length.
    try testing.expectError(error.MalformedResponse, pdu.parseReadRegistersResponse(
        &.{ 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00 },
        .read_holding_registers,
        &regs,
    ));
    var bits: [10]bool = undefined;
    try testing.expectError(error.MalformedResponse, pdu.parseReadBitsResponse(
        &.{ 0x01, 0x01, 0xCD },
        .read_coils,
        &bits,
    ));
    // Write echoes that do not match the request.
    try testing.expectError(error.MalformedResponse, pdu.parseWriteSingleResponse(
        &.{ 0x06, 0x00, 0x02, 0x00, 0x03 },
        .write_single_register,
        0x0001,
        0x0003,
    ));
    try testing.expectError(error.MalformedResponse, pdu.parseWriteMultipleResponse(
        &.{ 0x10, 0x00, 0x01, 0x00, 0x03 },
        .write_multiple_registers,
        0x0001,
        2,
    ));
    try testing.expectError(error.MalformedResponse, pdu.parseWriteMultipleResponse(
        &.{ 0x10, 0x00, 0x01, 0x00 },
        .write_multiple_registers,
        0x0001,
        2,
    ));
}

test "garbage frames never panic" {
    var state: u32 = 0x2545F491;
    var frame: [300]u8 = undefined;
    var regs: [125]u16 = undefined;
    var bits: [64]bool = undefined;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        const len = state % (frame.len + 1);
        for (frame[0..len]) |*b| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            b.* = @truncate(state);
        }
        const bytes = frame[0..len];
        _ = tcp.decodeAdu(bytes) catch {};
        _ = rtu.decodeAdu(bytes) catch {};
        pdu.parseReadRegistersResponse(bytes, .read_holding_registers, &regs) catch {};
        pdu.parseReadBitsResponse(bytes, .read_coils, &bits) catch {};
        pdu.parseWriteSingleResponse(bytes, .write_single_register, 1, 2) catch {};
        pdu.parseWriteMultipleResponse(bytes, .write_multiple_registers, 1, 2) catch {};
    }
}

test "meta is well-formed" {
    try testing.expectEqual(.gap, meta.status);
    try testing.expectEqual(.any, meta.platform);
    try testing.expectEqual(.client, meta.role);
}
