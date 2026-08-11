// SPDX-License-Identifier: MIT

//! modbus.server — the **slave** side of the conversation, as a pure function
//! from one request frame to one reply frame.
//!
//! Its reason to exist is fleet simulation. A responder that speaks the real
//! wire format lets a whole Modbus master stack — including this module's own
//! `Client` — be exercised against hundreds of simulated field devices with no
//! hardware, and it is what makes the round-trip tests in `goldens.zig`
//! possible.
//!
//! It is deliberately **not** a PLC emulator: there is no scan cycle, no
//! program execution, no retentive-memory semantics. The four Modbus data
//! areas are plain caller-owned slices, and reads and writes hit them
//! directly.
//!
//! Shape (the same one `iec104`'s outstation and `s7comm`'s responder use):
//!
//! - `handleAdu(request, out) -> ?[]u8` takes one whole ADU and writes one
//!   whole ADU, so a caller can drive it from any transport — or from none,
//!   which is what the tests do. `null` means "say nothing": a broadcast, a
//!   frame for a different slave, or a frame that failed its CRC.
//! - `handlePdu(request, out) -> []u8` is the same thing one layer down, for
//!   callers that already own their framing (a gateway, a fuzz harness).
//! - No threads, no timers, no allocation. Every buffer is the caller's.
//!
//! Address ranges are **explicit**: every area carries a base address plus its
//! storage, so a request outside the configured window is a real
//! `IllegalDataAddress` exception rather than a silent wrap into a neighbour's
//! data.
//!
//! Provenance: clean-room from the public Modbus Application Protocol
//! Specification V1.1b3 (§6.1–6.17 request/response layouts, §7 exception
//! codes) and Modbus over Serial Line V1.02 (§2.4 broadcast, §4 RTU framing).
//! Behaviour cross-checked against pymodbus (BSD-3-Clause) as a black-box
//! peer only — its master drove this responder over a real socket; no source
//! was consulted or copied.

const std = @import("std");
const mb = @import("root.zig");

const FunctionCode = mb.FunctionCode;
const ExceptionCode = mb.ExceptionCode;
const limits = mb.limits;

// ── data model ──────────────────────────────────────────────────────────────

/// One of the four Modbus data areas.
pub const Area = enum {
    coils,
    discrete_inputs,
    holding_registers,
    input_registers,
};

/// A window of bit-addressed storage: `values[i]` is the point at address
/// `base + i`. An empty `values` means the area is not implemented, and every
/// request touching it is answered `IllegalDataAddress`.
pub const BitArea = struct {
    base: u16 = 0,
    values: []bool = &.{},

    /// Index of `addr` within this window, or null when out of range.
    pub fn index(self: BitArea, addr: u16) ?usize {
        if (addr < self.base) return null;
        const off = addr - self.base;
        if (off >= self.values.len) return null;
        return off;
    }

    /// True when the whole span `addr .. addr+count-1` lies inside the window.
    pub fn contains(self: BitArea, addr: u16, count: u16) bool {
        if (count == 0) return false;
        if (addr < self.base) return false;
        const off: u32 = @as(u32, addr) - self.base;
        return off + count <= self.values.len;
    }
};

/// A window of 16-bit register storage; same conventions as `BitArea`.
pub const RegisterArea = struct {
    base: u16 = 0,
    values: []u16 = &.{},

    pub fn index(self: RegisterArea, addr: u16) ?usize {
        if (addr < self.base) return null;
        const off = addr - self.base;
        if (off >= self.values.len) return null;
        return off;
    }

    pub fn contains(self: RegisterArea, addr: u16, count: u16) bool {
        if (count == 0) return false;
        if (addr < self.base) return false;
        const off: u32 = @as(u32, addr) - self.base;
        return off + count <= self.values.len;
    }
};

/// The point database: four caller-owned windows. Nothing is copied and
/// nothing is allocated — the caller may mutate the backing slices between
/// calls (that is how a simulator animates its process image).
pub const DataBank = struct {
    coils: BitArea = .{},
    discrete_inputs: BitArea = .{},
    holding_registers: RegisterArea = .{},
    input_registers: RegisterArea = .{},
};

// ── write notification ──────────────────────────────────────────────────────

pub const WriteEvent = struct {
    area: Area, // always .coils or .holding_registers
    addr: u16,
    count: u16,
};

/// Optional post-write notification, invoked after the data bank has already
/// been updated and before the reply is built. A simulator uses it to drive
/// whatever the write is supposed to actuate.
pub const WriteHook = struct {
    ctx: *anyopaque,
    onWriteFn: *const fn (ctx: *anyopaque, event: WriteEvent) void,

    pub fn notify(self: WriteHook, event: WriteEvent) void {
        self.onWriteFn(self.ctx, event);
    }
};

// ── configuration ───────────────────────────────────────────────────────────

pub const Config = struct {
    /// The slave address / unit id this server answers for. On RTU this is
    /// the wire address (1..247 for a standard device); on TCP it is the MBAP
    /// unit id.
    unit_id: u8,

    /// Framing this server expects on `handleAdu`.
    framing: mb.Framing,

    /// Answer *any* unit id (gateway / "don't care" mode). Off by default:
    /// a simulator that answers for addresses it was not given teaches its
    /// operator the wrong lesson.
    accept_any_unit: bool = false,

    /// TCP only. The MBAP unit id 0 conventionally means "the device I am
    /// directly connected to" rather than the serial broadcast address, and
    /// most TCP masters send it when they do not care. Ignored for RTU, where
    /// address 0 is always a broadcast.
    tcp_accept_unit_0: bool = true,

    /// TCP only. Unit id 255 is the other widely-used "directly connected
    /// device" convention (the Modbus-TCP implementation guide's suggested
    /// value for a non-bridging server).
    tcp_accept_unit_255: bool = true,

    /// FC 0x07 Read Exception Status payload. `null` means the function is
    /// not implemented and requests for it are answered `IllegalFunction`.
    exception_status: ?u8 = null,

    /// FC 0x11 Report Slave ID: the device-specific id bytes. Empty means the
    /// function is not implemented (`IllegalFunction`).
    slave_id: []const u8 = &.{},

    /// FC 0x11 run-indicator status: 0xFF when true (ON), 0x00 when false.
    run_indicator: bool = true,

    /// FC 0x11 additional device data appended after the run indicator.
    slave_id_extra: []const u8 = &.{},

    /// FC 0x08 Diagnostics. When false, every sub-function is answered
    /// `IllegalFunction`.
    diagnostics: bool = true,

    /// FC 0x17 Read/Write Multiple Registers.
    read_write_registers: bool = true,
};

/// The serial-line diagnostic counters (application spec §6.8 sub-functions
/// 0x0B..0x12). Maintained by `handleAdu`; a caller that owns its own framing
/// and calls `handlePdu` directly maintains whichever of them it cares about.
pub const Counters = struct {
    /// 0x0B: messages the device has detected on the bus.
    bus_message: u16 = 0,
    /// 0x0C: CRC errors.
    bus_comm_error: u16 = 0,
    /// 0x0D: exception responses returned.
    slave_exception_error: u16 = 0,
    /// 0x0E: messages addressed to this slave (incl. broadcast).
    slave_message: u16 = 0,
    /// 0x0F: messages addressed to this slave for which no response was
    /// returned (broadcasts).
    slave_no_response: u16 = 0,

    pub fn clear(self: *Counters) void {
        self.* = .{};
    }
};

/// The only failure `handlePdu` / `handleAdu` can report: everything a
/// *peer* can get wrong becomes an exception response or a dropped frame,
/// never an error. This is a local programming mistake — the output buffer
/// must hold `tcp.max_adu_len` (260) bytes to be always sufficient.
pub const Error = error{BufferTooSmall};

// ── diagnostics sub-function codes (§6.8) ──────────────────────────────────

pub const DiagnosticSubFunction = enum(u16) {
    return_query_data = 0x0000,
    restart_comm_option = 0x0001,
    force_listen_only_mode = 0x0004,
    clear_counters = 0x000A,
    bus_message_count = 0x000B,
    bus_comm_error_count = 0x000C,
    slave_exception_error_count = 0x000D,
    slave_message_count = 0x000E,
    slave_no_response_count = 0x000F,
    _,
};

// ── the server ──────────────────────────────────────────────────────────────

pub const Server = struct {
    config: Config,
    db: DataBank,
    hook: ?WriteHook = null,
    counters: Counters = .{},
    /// Set by diagnostics sub-function 0x0004. While on, the device processes
    /// nothing but diagnostics 0x0001 (restart) and returns no responses at
    /// all — exactly what §6.8 asks for.
    listen_only: bool = false,
    /// Length of the reply the last successful handler wrote into `out`.
    /// Handlers return an optional exception code, so the length travels
    /// through this field rather than the return value — it keeps every
    /// handler's signature identical and the dispatch table readable.
    reply_len: usize = 0,

    pub fn init(config: Config, db: DataBank) Server {
        return .{ .config = config, .db = db };
    }

    /// Attach (or replace) the post-write notification hook.
    pub fn setWriteHook(self: *Server, hook: ?WriteHook) void {
        self.hook = hook;
    }

    // ── ADU layer ───────────────────────────────────────────────────────────

    /// Handles one complete request ADU and writes one complete reply ADU
    /// into `out`.
    ///
    /// Returns `null` — "stay silent" — for every case where a real device
    /// stays silent:
    ///
    /// - an RTU frame whose CRC does not check out (§ Serial Line 2.5.1.1:
    ///   discarded, *never* answered with an exception — answering would let
    ///   a corrupted address field pull two slaves onto the bus at once);
    /// - an RTU frame addressed to a different slave;
    /// - an RTU broadcast (address 0): the write **is** applied, but nothing
    ///   is sent back;
    /// - a TCP frame for a unit id this server does not answer for;
    /// - a structurally impossible frame (short, over-long, bad MBAP length
    ///   or protocol id).
    ///
    /// `out` must be at least `mb.tcp.max_adu_len` bytes.
    pub fn handleAdu(self: *Server, adu: []const u8, out: []u8) Error!?[]u8 {
        switch (self.config.framing) {
            .tcp => {
                const frame = mb.tcp.decodeAdu(adu) catch return null;
                self.counters.bus_message +%= 1;
                if (!self.acceptsUnit(frame.unit)) return null;
                self.counters.slave_message +%= 1;
                if (self.listen_only and !isRestartDiagnostic(frame.pdu)) {
                    self.counters.slave_no_response +%= 1;
                    return null;
                }

                var pdu_buf: [mb.max_pdu_len]u8 = undefined;
                const was_listening = self.listen_only;
                const reply_pdu = try self.handlePdu(frame.pdu, &pdu_buf);
                if (!was_listening and self.listen_only) {
                    self.counters.slave_no_response +%= 1;
                    return null;
                }
                return mb.tcp.encodeAdu(out, frame.transaction_id, frame.unit, reply_pdu) catch
                    return error.BufferTooSmall;
            },
            .rtu => {
                const frame = mb.rtu.decodeAdu(adu) catch |err| {
                    self.counters.bus_message +%= 1;
                    if (err == error.BadCrc) self.counters.bus_comm_error +%= 1;
                    return null;
                };
                self.counters.bus_message +%= 1;

                const broadcast = frame.unit == 0;
                if (!broadcast and !self.acceptsUnit(frame.unit)) return null;
                self.counters.slave_message +%= 1;

                if (self.listen_only and !isRestartDiagnostic(frame.pdu)) {
                    self.counters.slave_no_response +%= 1;
                    return null;
                }

                var pdu_buf: [mb.max_pdu_len]u8 = undefined;
                const was_listening = self.listen_only;
                const reply_pdu = try self.handlePdu(frame.pdu, &pdu_buf);
                if (!was_listening and self.listen_only) {
                    // §6.8 sub 0x0004: the request that puts the device into
                    // listen-only mode is itself not answered.
                    self.counters.slave_no_response +%= 1;
                    return null;
                }
                if (broadcast) {
                    // The write has already been applied; a broadcast is never
                    // answered (§ Serial Line 2.4.1).
                    self.counters.slave_no_response +%= 1;
                    return null;
                }
                return mb.rtu.encodeAdu(out, frame.unit, reply_pdu) catch
                    return error.BufferTooSmall;
            },
        }
    }

    fn acceptsUnit(self: *const Server, unit: u8) bool {
        if (self.config.accept_any_unit) return true;
        if (unit == self.config.unit_id) return true;
        if (self.config.framing == .tcp) {
            if (unit == 0 and self.config.tcp_accept_unit_0) return true;
            if (unit == 0xFF and self.config.tcp_accept_unit_255) return true;
        }
        return false;
    }

    fn isRestartDiagnostic(request: []const u8) bool {
        return request.len >= 3 and
            request[0] == @intFromEnum(FunctionCode.diagnostics) and
            std.mem.readInt(u16, request[1..3], .big) == @intFromEnum(DiagnosticSubFunction.restart_comm_option);
    }

    // ── PDU layer ───────────────────────────────────────────────────────────

    /// Handles one request PDU (function code + data, no framing) and writes
    /// the reply PDU into `out`. Always produces a reply — an exception
    /// response when the request cannot be honoured. `out` must be at least
    /// `mb.max_pdu_len` (253) bytes.
    ///
    /// Broadcast semantics live one layer up in `handleAdu`: this function
    /// always builds a reply, and the ADU layer decides whether to send it.
    pub fn handlePdu(self: *Server, request: []const u8, out: []u8) Error![]u8 {
        if (out.len < mb.max_pdu_len) return error.BufferTooSmall;
        if (request.len == 0) {
            // Nothing to echo a function code from; the closest honest answer
            // is an illegal-function exception on function 0.
            return self.exception(out, 0, .illegal_function);
        }
        const fc_byte = request[0];
        const body = request[1..];

        const result: ?ExceptionCode = switch (fc_byte) {
            @intFromEnum(FunctionCode.read_coils) => self.doReadBits(.coils, body, out),
            @intFromEnum(FunctionCode.read_discrete_inputs) => self.doReadBits(.discrete_inputs, body, out),
            @intFromEnum(FunctionCode.read_holding_registers) => self.doReadRegisters(.holding_registers, body, out),
            @intFromEnum(FunctionCode.read_input_registers) => self.doReadRegisters(.input_registers, body, out),
            @intFromEnum(FunctionCode.write_single_coil) => self.doWriteSingleCoil(body, out),
            @intFromEnum(FunctionCode.write_single_register) => self.doWriteSingleRegister(body, out),
            @intFromEnum(FunctionCode.write_multiple_coils) => self.doWriteMultipleCoils(body, out),
            @intFromEnum(FunctionCode.write_multiple_registers) => self.doWriteMultipleRegisters(body, out),
            @intFromEnum(FunctionCode.read_write_multiple_registers) => self.doReadWriteRegisters(body, out),
            @intFromEnum(FunctionCode.read_exception_status) => self.doReadExceptionStatus(body, out),
            @intFromEnum(FunctionCode.diagnostics) => self.doDiagnostics(body, out),
            @intFromEnum(FunctionCode.report_slave_id) => self.doReportSlaveId(body, out),
            else => .illegal_function,
        };

        if (result) |code| return self.exception(out, fc_byte, code);
        return out[0..self.reply_len];
    }

    fn exception(self: *Server, out: []u8, fc_byte: u8, code: ExceptionCode) []u8 {
        self.counters.slave_exception_error +%= 1;
        out[0] = fc_byte | 0x80;
        out[1] = @intFromEnum(code);
        self.reply_len = 2;
        return out[0..2];
    }

    // ── FC 0x01 / 0x02 ──────────────────────────────────────────────────────

    fn doReadBits(self: *Server, area: Area, body: []const u8, out: []u8) ?ExceptionCode {
        if (body.len != 4) return .illegal_data_value;
        const addr = std.mem.readInt(u16, body[0..2], .big);
        const quantity = std.mem.readInt(u16, body[2..4], .big);
        if (quantity == 0 or quantity > limits.max_read_bits) return .illegal_data_value;

        const bits: BitArea = switch (area) {
            .coils => self.db.coils,
            .discrete_inputs => self.db.discrete_inputs,
            else => unreachable,
        };
        if (!bits.contains(addr, quantity)) return .illegal_data_address;

        const nbytes = mb.bitByteCount(quantity);
        out[0] = if (area == .coils)
            @intFromEnum(FunctionCode.read_coils)
        else
            @intFromEnum(FunctionCode.read_discrete_inputs);
        out[1] = @intCast(nbytes);
        @memset(out[2..][0..nbytes], 0);
        const start = bits.index(addr).?;
        for (0..quantity) |i| {
            if (bits.values[start + i]) {
                const shift: u3 = @intCast(i % 8);
                out[2 + i / 8] |= @as(u8, 1) << shift;
            }
        }
        self.reply_len = 2 + nbytes;
        return null;
    }

    // ── FC 0x03 / 0x04 ──────────────────────────────────────────────────────

    fn doReadRegisters(self: *Server, area: Area, body: []const u8, out: []u8) ?ExceptionCode {
        if (body.len != 4) return .illegal_data_value;
        const addr = std.mem.readInt(u16, body[0..2], .big);
        const quantity = std.mem.readInt(u16, body[2..4], .big);
        if (quantity == 0 or quantity > limits.max_read_registers) return .illegal_data_value;

        const regs: RegisterArea = switch (area) {
            .holding_registers => self.db.holding_registers,
            .input_registers => self.db.input_registers,
            else => unreachable,
        };
        if (!regs.contains(addr, quantity)) return .illegal_data_address;

        out[0] = if (area == .holding_registers)
            @intFromEnum(FunctionCode.read_holding_registers)
        else
            @intFromEnum(FunctionCode.read_input_registers);
        out[1] = @intCast(2 * quantity);
        const start = regs.index(addr).?;
        for (0..quantity) |i| {
            std.mem.writeInt(u16, out[2 + 2 * i ..][0..2], regs.values[start + i], .big);
        }
        self.reply_len = 2 + 2 * @as(usize, quantity);
        return null;
    }

    // ── FC 0x05 ─────────────────────────────────────────────────────────────

    fn doWriteSingleCoil(self: *Server, body: []const u8, out: []u8) ?ExceptionCode {
        if (body.len != 4) return .illegal_data_value;
        const addr = std.mem.readInt(u16, body[0..2], .big);
        const value = std.mem.readInt(u16, body[2..4], .big);
        // §6.5: only 0xFF00 (ON) and 0x0000 (OFF) are allowable.
        const on = switch (value) {
            0xFF00 => true,
            0x0000 => false,
            else => return .illegal_data_value,
        };
        const idx = self.db.coils.index(addr) orelse return .illegal_data_address;
        self.db.coils.values[idx] = on;
        if (self.hook) |h| h.notify(.{ .area = .coils, .addr = addr, .count = 1 });

        // The response is an exact echo of the request.
        out[0] = @intFromEnum(FunctionCode.write_single_coil);
        @memcpy(out[1..5], body[0..4]);
        self.reply_len = 5;
        return null;
    }

    // ── FC 0x06 ─────────────────────────────────────────────────────────────

    fn doWriteSingleRegister(self: *Server, body: []const u8, out: []u8) ?ExceptionCode {
        if (body.len != 4) return .illegal_data_value;
        const addr = std.mem.readInt(u16, body[0..2], .big);
        const value = std.mem.readInt(u16, body[2..4], .big);
        const idx = self.db.holding_registers.index(addr) orelse return .illegal_data_address;
        self.db.holding_registers.values[idx] = value;
        if (self.hook) |h| h.notify(.{ .area = .holding_registers, .addr = addr, .count = 1 });

        out[0] = @intFromEnum(FunctionCode.write_single_register);
        @memcpy(out[1..5], body[0..4]);
        self.reply_len = 5;
        return null;
    }

    // ── FC 0x0F ─────────────────────────────────────────────────────────────

    fn doWriteMultipleCoils(self: *Server, body: []const u8, out: []u8) ?ExceptionCode {
        if (body.len < 5) return .illegal_data_value;
        const addr = std.mem.readInt(u16, body[0..2], .big);
        const quantity = std.mem.readInt(u16, body[2..4], .big);
        const byte_count: usize = body[4];
        if (quantity == 0 or quantity > limits.max_write_bits) return .illegal_data_value;
        // The declared byte count must agree with the quantity *and* with the
        // bytes actually present — a PDU where those disagree is exactly the
        // hostile input this check exists for.
        if (byte_count != mb.bitByteCount(quantity)) return .illegal_data_value;
        if (body.len != 5 + byte_count) return .illegal_data_value;
        if (!self.db.coils.contains(addr, quantity)) return .illegal_data_address;

        const start = self.db.coils.index(addr).?;
        const data = body[5..];
        for (0..quantity) |i| {
            const shift: u3 = @intCast(i % 8);
            self.db.coils.values[start + i] = (data[i / 8] >> shift) & 1 != 0;
        }
        if (self.hook) |h| h.notify(.{ .area = .coils, .addr = addr, .count = quantity });

        out[0] = @intFromEnum(FunctionCode.write_multiple_coils);
        @memcpy(out[1..5], body[0..4]); // echo start address + quantity
        self.reply_len = 5;
        return null;
    }

    // ── FC 0x10 ─────────────────────────────────────────────────────────────

    fn doWriteMultipleRegisters(self: *Server, body: []const u8, out: []u8) ?ExceptionCode {
        if (body.len < 5) return .illegal_data_value;
        const addr = std.mem.readInt(u16, body[0..2], .big);
        const quantity = std.mem.readInt(u16, body[2..4], .big);
        const byte_count: usize = body[4];
        if (quantity == 0 or quantity > limits.max_write_registers) return .illegal_data_value;
        if (byte_count != 2 * @as(usize, quantity)) return .illegal_data_value;
        if (body.len != 5 + byte_count) return .illegal_data_value;
        if (!self.db.holding_registers.contains(addr, quantity)) return .illegal_data_address;

        const start = self.db.holding_registers.index(addr).?;
        const data = body[5..];
        for (0..quantity) |i| {
            self.db.holding_registers.values[start + i] =
                std.mem.readInt(u16, data[2 * i ..][0..2], .big);
        }
        if (self.hook) |h| h.notify(.{ .area = .holding_registers, .addr = addr, .count = quantity });

        out[0] = @intFromEnum(FunctionCode.write_multiple_registers);
        @memcpy(out[1..5], body[0..4]);
        self.reply_len = 5;
        return null;
    }

    // ── FC 0x17 ─────────────────────────────────────────────────────────────

    fn doReadWriteRegisters(self: *Server, body: []const u8, out: []u8) ?ExceptionCode {
        if (!self.config.read_write_registers) return .illegal_function;
        if (body.len < 9) return .illegal_data_value;
        const read_addr = std.mem.readInt(u16, body[0..2], .big);
        const read_quantity = std.mem.readInt(u16, body[2..4], .big);
        const write_addr = std.mem.readInt(u16, body[4..6], .big);
        const write_quantity = std.mem.readInt(u16, body[6..8], .big);
        const byte_count: usize = body[8];

        if (read_quantity == 0 or read_quantity > limits.max_rw_read_registers) return .illegal_data_value;
        if (write_quantity == 0 or write_quantity > limits.max_rw_write_registers) return .illegal_data_value;
        if (byte_count != 2 * @as(usize, write_quantity)) return .illegal_data_value;
        if (body.len != 9 + byte_count) return .illegal_data_value;

        if (!self.db.holding_registers.contains(read_addr, read_quantity)) return .illegal_data_address;
        if (!self.db.holding_registers.contains(write_addr, write_quantity)) return .illegal_data_address;

        // §6.17: the write operation is performed before the read.
        const write_start = self.db.holding_registers.index(write_addr).?;
        const data = body[9..];
        for (0..write_quantity) |i| {
            self.db.holding_registers.values[write_start + i] =
                std.mem.readInt(u16, data[2 * i ..][0..2], .big);
        }
        if (self.hook) |h| h.notify(.{ .area = .holding_registers, .addr = write_addr, .count = write_quantity });

        const read_start = self.db.holding_registers.index(read_addr).?;
        out[0] = @intFromEnum(FunctionCode.read_write_multiple_registers);
        out[1] = @intCast(2 * read_quantity);
        for (0..read_quantity) |i| {
            std.mem.writeInt(u16, out[2 + 2 * i ..][0..2], self.db.holding_registers.values[read_start + i], .big);
        }
        self.reply_len = 2 + 2 * @as(usize, read_quantity);
        return null;
    }

    // ── FC 0x07 ─────────────────────────────────────────────────────────────

    fn doReadExceptionStatus(self: *Server, body: []const u8, out: []u8) ?ExceptionCode {
        const status = self.config.exception_status orelse return .illegal_function;
        if (body.len != 0) return .illegal_data_value;
        out[0] = @intFromEnum(FunctionCode.read_exception_status);
        out[1] = status;
        self.reply_len = 2;
        return null;
    }

    // ── FC 0x08 ─────────────────────────────────────────────────────────────

    fn doDiagnostics(self: *Server, body: []const u8, out: []u8) ?ExceptionCode {
        if (!self.config.diagnostics) return .illegal_function;
        if (body.len < 2) return .illegal_data_value;
        const sub: DiagnosticSubFunction = @enumFromInt(std.mem.readInt(u16, body[0..2], .big));
        const data = body[2..];

        out[0] = @intFromEnum(FunctionCode.diagnostics);
        @memcpy(out[1..3], body[0..2]);

        switch (sub) {
            // 0x00 Return Query Data: echo the request data back verbatim.
            .return_query_data => {
                if (3 + data.len > mb.max_pdu_len) return .illegal_data_value;
                @memcpy(out[3..][0..data.len], data);
                self.reply_len = 3 + data.len;
                return null;
            },
            // 0x01 Restart Communications Option: leaves listen-only mode.
            // Data 0x0000 keeps the log, 0xFF00 clears the counters.
            .restart_comm_option => {
                if (data.len != 2) return .illegal_data_value;
                const arg = std.mem.readInt(u16, data[0..2], .big);
                if (arg != 0x0000 and arg != 0xFF00) return .illegal_data_value;
                self.listen_only = false;
                if (arg == 0xFF00) self.counters.clear();
                @memcpy(out[3..5], data[0..2]);
                self.reply_len = 5;
                return null;
            },
            // 0x04 Force Listen Only Mode: no response is returned for this
            // one either, but the ADU layer needs a reply PDU to discard, so
            // build the echo and let `handleAdu` swallow it.
            .force_listen_only_mode => {
                if (data.len != 2 or std.mem.readInt(u16, data[0..2], .big) != 0) return .illegal_data_value;
                self.listen_only = true;
                @memcpy(out[3..5], data[0..2]);
                self.reply_len = 5;
                return null;
            },
            .clear_counters => {
                if (data.len != 2 or std.mem.readInt(u16, data[0..2], .big) != 0) return .illegal_data_value;
                self.counters.clear();
                std.mem.writeInt(u16, out[3..5], 0, .big);
                self.reply_len = 5;
                return null;
            },
            .bus_message_count,
            .bus_comm_error_count,
            .slave_exception_error_count,
            .slave_message_count,
            .slave_no_response_count,
            => {
                if (data.len != 2 or std.mem.readInt(u16, data[0..2], .big) != 0) return .illegal_data_value;
                const value: u16 = switch (sub) {
                    .bus_message_count => self.counters.bus_message,
                    .bus_comm_error_count => self.counters.bus_comm_error,
                    .slave_exception_error_count => self.counters.slave_exception_error,
                    .slave_message_count => self.counters.slave_message,
                    .slave_no_response_count => self.counters.slave_no_response,
                    else => unreachable,
                };
                std.mem.writeInt(u16, out[3..5], value, .big);
                self.reply_len = 5;
                return null;
            },
            // §6.8: an unsupported sub-function is an illegal function, not an
            // illegal data value.
            _ => return .illegal_function,
        }
    }

    // ── FC 0x11 ─────────────────────────────────────────────────────────────

    fn doReportSlaveId(self: *Server, body: []const u8, out: []u8) ?ExceptionCode {
        if (self.config.slave_id.len == 0) return .illegal_function;
        if (body.len != 0) return .illegal_data_value;
        const count = self.config.slave_id.len + 1 + self.config.slave_id_extra.len;
        if (count > 0xFF or 2 + count > mb.max_pdu_len) return .server_device_failure;

        out[0] = @intFromEnum(FunctionCode.report_slave_id);
        out[1] = @intCast(count);
        var pos: usize = 2;
        @memcpy(out[pos..][0..self.config.slave_id.len], self.config.slave_id);
        pos += self.config.slave_id.len;
        out[pos] = if (self.config.run_indicator) 0xFF else 0x00;
        pos += 1;
        @memcpy(out[pos..][0..self.config.slave_id_extra.len], self.config.slave_id_extra);
        pos += self.config.slave_id_extra.len;
        self.reply_len = pos;
        return null;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A small device used by most tests below: coils 0..15, discrete inputs
/// 0..15, holding registers 100..115, input registers 200..207.
const Fixture = struct {
    coils: [16]bool = [_]bool{false} ** 16,
    discretes: [16]bool = [_]bool{false} ** 16,
    holdings: [16]u16 = [_]u16{0} ** 16,
    inputs: [8]u16 = [_]u16{0} ** 8,

    fn server(self: *Fixture, framing: mb.Framing) Server {
        return Server.init(.{ .unit_id = 5, .framing = framing }, .{
            .coils = .{ .base = 0, .values = &self.coils },
            .discrete_inputs = .{ .base = 0, .values = &self.discretes },
            .holding_registers = .{ .base = 100, .values = &self.holdings },
            .input_registers = .{ .base = 200, .values = &self.inputs },
        });
    }
};

fn expectException(reply: []const u8, fc: u8, code: ExceptionCode) !void {
    try testing.expectEqual(@as(usize, 2), reply.len);
    try testing.expectEqual(fc | 0x80, reply[0]);
    try testing.expectEqual(@intFromEnum(code), reply[1]);
}

// ── address windows ─────────────────────────────────────────────────────────

test "address windows: a request outside the window is IllegalDataAddress, never a wrap" {
    var fix = Fixture{};
    fix.holdings[0] = 0xAA55;
    var server = fix.server(.rtu);
    var out: [mb.max_pdu_len]u8 = undefined;

    // In range: register 100 is holdings[0].
    const ok = try server.handlePdu(&.{ 0x03, 0x00, 0x64, 0x00, 0x01 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x02, 0xAA, 0x55 }, ok);

    // One below the base.
    try expectException(
        try server.handlePdu(&.{ 0x03, 0x00, 0x63, 0x00, 0x01 }, &out),
        0x03,
        .illegal_data_address,
    );
    // Straddling the top edge: 115 is the last register, 116 is not.
    try expectException(
        try server.handlePdu(&.{ 0x03, 0x00, 0x73, 0x00, 0x02 }, &out),
        0x03,
        .illegal_data_address,
    );
    // Entirely past the top.
    try expectException(
        try server.handlePdu(&.{ 0x03, 0xFF, 0x00, 0x00, 0x01 }, &out),
        0x03,
        .illegal_data_address,
    );
    // A span that would overflow the 16-bit address space.
    try expectException(
        try server.handlePdu(&.{ 0x03, 0xFF, 0xFF, 0x00, 0x02 }, &out),
        0x03,
        .illegal_data_address,
    );
}

test "address windows: an unimplemented area answers IllegalDataAddress, not a crash" {
    var coils = [_]bool{false} ** 8;
    // Only coils exist; the other three areas are empty.
    var server = Server.init(
        .{ .unit_id = 1, .framing = .rtu },
        .{ .coils = .{ .base = 0, .values = &coils } },
    );
    var out: [mb.max_pdu_len]u8 = undefined;
    for ([_]u8{ 0x02, 0x03, 0x04 }) |fc| {
        try expectException(
            try server.handlePdu(&.{ fc, 0x00, 0x00, 0x00, 0x01 }, &out),
            fc,
            .illegal_data_address,
        );
    }
    try expectException(
        try server.handlePdu(&.{ 0x06, 0x00, 0x00, 0x00, 0x01 }, &out),
        0x06,
        .illegal_data_address,
    );
}

test "address windows: base offsets are honoured on every area" {
    var fix = Fixture{};
    fix.inputs[3] = 0xDEAD;
    var server = fix.server(.rtu);
    var out: [mb.max_pdu_len]u8 = undefined;

    // Input register 203 == inputs[3].
    const reply = try server.handlePdu(&.{ 0x04, 0x00, 0xCB, 0x00, 0x01 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x02, 0xDE, 0xAD }, reply);

    // Holding register 100 is not input register 100.
    try expectException(
        try server.handlePdu(&.{ 0x04, 0x00, 0x64, 0x00, 0x01 }, &out),
        0x04,
        .illegal_data_address,
    );
}

// ── quantity limits ─────────────────────────────────────────────────────────

test "quantity limits: over-large reads are IllegalDataValue, not truncated reads" {
    var bits = [_]bool{false} ** 3000;
    var regs = [_]u16{0} ** 200;
    var server = Server.init(.{ .unit_id = 1, .framing = .rtu }, .{
        .coils = .{ .base = 0, .values = &bits },
        .discrete_inputs = .{ .base = 0, .values = &bits },
        .holding_registers = .{ .base = 0, .values = &regs },
        .input_registers = .{ .base = 0, .values = &regs },
    });
    var out: [mb.max_pdu_len]u8 = undefined;

    // FC 01/02: 2000 is the limit (0x07D0), 2001 is not.
    for ([_]u8{ 0x01, 0x02 }) |fc| {
        const ok = try server.handlePdu(&.{ fc, 0x00, 0x00, 0x07, 0xD0 }, &out);
        try testing.expectEqual(@as(usize, 2 + 250), ok.len);
        try expectException(
            try server.handlePdu(&.{ fc, 0x00, 0x00, 0x07, 0xD1 }, &out),
            fc,
            .illegal_data_value,
        );
        try expectException(
            try server.handlePdu(&.{ fc, 0x00, 0x00, 0x00, 0x00 }, &out),
            fc,
            .illegal_data_value,
        );
    }

    // FC 03/04: 125 is the limit (0x7D).
    for ([_]u8{ 0x03, 0x04 }) |fc| {
        const ok = try server.handlePdu(&.{ fc, 0x00, 0x00, 0x00, 0x7D }, &out);
        try testing.expectEqual(@as(usize, 2 + 250), ok.len);
        try expectException(
            try server.handlePdu(&.{ fc, 0x00, 0x00, 0x00, 0x7E }, &out),
            fc,
            .illegal_data_value,
        );
        try expectException(
            try server.handlePdu(&.{ fc, 0x00, 0x00, 0x00, 0x00 }, &out),
            fc,
            .illegal_data_value,
        );
    }
}

test "quantity limits: over-large writes are IllegalDataValue, and only because of the limit" {
    // Audit finding `modbus` F2: the old version of this test built each
    // probe PDU with a header only (no data bytes) and, separately, a byte
    // count that did not match the quantity either — so a probe was
    // rejected by *two* independent checks at once (`byte_count !=
    // expected` and `body.len != 5 + byte_count`, both `server.zig`) and
    // this test could not tell which one actually fired. Raising the
    // relevant limit by one left it green, because the byte-count/length
    // check took over — proven by fault injection: `limits.max_write_registers`
    // 123 -> 124 flipped the *client* encoder test (`root.zig`) red but left
    // this one green.
    //
    // Every PDU built below is otherwise completely well-formed — byte
    // count matches the quantity, body length matches the byte count, and
    // the address window (a 3000-coil / 200-register backing store) is wide
    // enough to succeed — so the *only* reason any of them is rejected is
    // the quantity limit itself. Confirmed live: bumping the matching
    // `limits.max_write_*`/`max_rw_*` constant by one turns the matching
    // probe below into a real accepted write (`reply.len == 5`, not an
    // exception), which fails `expectException` below rather than staying
    // green.
    var bits = [_]bool{false} ** 3000;
    var regs = [_]u16{0} ** 200;
    var server = Server.init(.{ .unit_id = 1, .framing = .rtu }, .{
        .coils = .{ .base = 0, .values = &bits },
        .holding_registers = .{ .base = 0, .values = &regs },
    });
    var out: [mb.max_pdu_len]u8 = undefined;

    // FC 0F: 1968 (0x07B0) coils is the limit; probe one over.
    {
        const qty: u16 = mb.limits.max_write_bits + 1;
        const byte_count = mb.bitByteCount(qty);
        var req: [1 + 5 + 247]u8 = undefined;
        try testing.expectEqual(@as(usize, 247), byte_count); // pin the shape
        req[0] = 0x0F;
        std.mem.writeInt(u16, req[1..3], 0, .big);
        std.mem.writeInt(u16, req[3..5], qty, .big);
        req[5] = @intCast(byte_count);
        @memset(req[6..], 0);
        try expectException(try server.handlePdu(&req, &out), 0x0F, .illegal_data_value);
    }

    // FC 10: 123 (0x7B) registers is the limit; probe one over.
    {
        const qty: u16 = mb.limits.max_write_registers + 1;
        const byte_count = 2 * @as(usize, qty);
        var req: [1 + 5 + 248]u8 = undefined;
        try testing.expectEqual(@as(usize, 248), byte_count);
        req[0] = 0x10;
        std.mem.writeInt(u16, req[1..3], 0, .big);
        std.mem.writeInt(u16, req[3..5], qty, .big);
        req[5] = @intCast(byte_count);
        @memset(req[6..], 0);
        try expectException(try server.handlePdu(&req, &out), 0x10, .illegal_data_value);
    }

    // FC 17: 125 read / 121 write are the limits — two probes, each
    // well-formed apart from the one quantity it targets.
    {
        // Read quantity one over (126); write quantity valid (1).
        const rq: u16 = mb.limits.max_rw_read_registers + 1;
        const wq: u16 = 1;
        const byte_count = 2 * @as(usize, wq);
        var req: [1 + 9 + 2]u8 = undefined;
        req[0] = 0x17;
        std.mem.writeInt(u16, req[1..3], 0, .big);
        std.mem.writeInt(u16, req[3..5], rq, .big);
        std.mem.writeInt(u16, req[5..7], 0, .big);
        std.mem.writeInt(u16, req[7..9], wq, .big);
        req[9] = @intCast(byte_count);
        @memset(req[10..], 0);
        try expectException(try server.handlePdu(&req, &out), 0x17, .illegal_data_value);
    }
    {
        // Write quantity one over (122); read quantity valid (1).
        const rq: u16 = 1;
        const wq: u16 = mb.limits.max_rw_write_registers + 1;
        const byte_count = 2 * @as(usize, wq);
        var req: [1 + 9 + 244]u8 = undefined;
        req[0] = 0x17;
        std.mem.writeInt(u16, req[1..3], 0, .big);
        std.mem.writeInt(u16, req[3..5], rq, .big);
        std.mem.writeInt(u16, req[5..7], 0, .big);
        std.mem.writeInt(u16, req[7..9], wq, .big);
        req[9] = @intCast(byte_count);
        @memset(req[10..], 0);
        try expectException(try server.handlePdu(&req, &out), 0x17, .illegal_data_value);
    }
}

// ── hostile / malformed PDUs ────────────────────────────────────────────────

test "hostile: a byte count that contradicts the quantity is IllegalDataValue" {
    var fix = Fixture{};
    var server = fix.server(.rtu);
    var out: [mb.max_pdu_len]u8 = undefined;

    // FC 0F: quantity 8 wants byte count 1; claim 2 (and supply 2).
    try expectException(
        try server.handlePdu(&.{ 0x0F, 0x00, 0x00, 0x00, 0x08, 0x02, 0xFF, 0xFF }, &out),
        0x0F,
        .illegal_data_value,
    );
    // ...claim 1 but supply 2 bytes: the PDU length disagrees.
    try expectException(
        try server.handlePdu(&.{ 0x0F, 0x00, 0x00, 0x00, 0x08, 0x01, 0xFF, 0xFF }, &out),
        0x0F,
        .illegal_data_value,
    );
    // ...claim 1 and supply none.
    try expectException(
        try server.handlePdu(&.{ 0x0F, 0x00, 0x00, 0x00, 0x08, 0x01 }, &out),
        0x0F,
        .illegal_data_value,
    );
    // FC 10: quantity 2 wants byte count 4.
    try expectException(
        try server.handlePdu(&.{ 0x10, 0x00, 0x64, 0x00, 0x02, 0x02, 0xFF, 0xFF }, &out),
        0x10,
        .illegal_data_value,
    );
    // FC 10: byte count 4 but only 2 bytes present.
    try expectException(
        try server.handlePdu(&.{ 0x10, 0x00, 0x64, 0x00, 0x02, 0x04, 0xFF, 0xFF }, &out),
        0x10,
        .illegal_data_value,
    );
    // FC 17: write byte count disagrees with write quantity.
    try expectException(
        try server.handlePdu(&.{
            0x17, 0x00, 0x64, 0x00, 0x01, 0x00, 0x64, 0x00, 0x02, 0x02, 0xFF, 0xFF,
        }, &out),
        0x17,
        .illegal_data_value,
    );

    // Nothing was written by any of them.
    for (fix.coils) |c| try testing.expect(!c);
    for (fix.holdings) |r| try testing.expectEqual(@as(u16, 0), r);
}

test "hostile: wrong-length PDUs for the fixed-size function codes" {
    var fix = Fixture{};
    var server = fix.server(.rtu);
    var out: [mb.max_pdu_len]u8 = undefined;

    for ([_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }) |fc| {
        // Too short.
        try expectException(try server.handlePdu(&.{ fc, 0x00 }, &out), fc, .illegal_data_value);
        try expectException(try server.handlePdu(&.{fc}, &out), fc, .illegal_data_value);
        // Too long.
        try expectException(
            try server.handlePdu(&.{ fc, 0x00, 0x00, 0x00, 0x01, 0x99 }, &out),
            fc,
            .illegal_data_value,
        );
    }
    // FC 07 and FC 11 take no data at all.
    var with_status = Server.init(
        .{ .unit_id = 1, .framing = .rtu, .exception_status = 0x11, .slave_id = "x" },
        .{},
    );
    try expectException(
        try with_status.handlePdu(&.{ 0x07, 0x00 }, &out),
        0x07,
        .illegal_data_value,
    );
    try expectException(
        try with_status.handlePdu(&.{ 0x11, 0x00 }, &out),
        0x11,
        .illegal_data_value,
    );
}

test "hostile: FC 05 accepts only 0xFF00 and 0x0000" {
    var fix = Fixture{};
    var server = fix.server(.rtu);
    var out: [mb.max_pdu_len]u8 = undefined;

    _ = try server.handlePdu(&.{ 0x05, 0x00, 0x03, 0xFF, 0x00 }, &out);
    try testing.expect(fix.coils[3]);
    _ = try server.handlePdu(&.{ 0x05, 0x00, 0x03, 0x00, 0x00 }, &out);
    try testing.expect(!fix.coils[3]);

    for ([_]u16{ 0x0001, 0x00FF, 0xFF01, 0xFFFF, 0x8000 }) |bad| {
        var req = [_]u8{ 0x05, 0x00, 0x03, 0, 0 };
        std.mem.writeInt(u16, req[3..5], bad, .big);
        try expectException(try server.handlePdu(&req, &out), 0x05, .illegal_data_value);
    }
    try testing.expect(!fix.coils[3]); // still off
}

test "hostile: an empty PDU and unknown function codes are IllegalFunction" {
    var fix = Fixture{};
    var server = fix.server(.rtu);
    var out: [mb.max_pdu_len]u8 = undefined;

    try expectException(try server.handlePdu(&.{}, &out), 0x00, .illegal_function);
    for ([_]u8{ 0x00, 0x09, 0x0B, 0x0C, 0x14, 0x15, 0x16, 0x18, 0x2B, 0x7F, 0x80, 0xFF }) |fc| {
        const reply = try server.handlePdu(&.{ fc, 0x00, 0x00 }, &out);
        try expectException(reply, fc, .illegal_function);
    }
}

test "hostile: a short output buffer is a typed error, not a stomp" {
    var fix = Fixture{};
    var server = fix.server(.tcp);
    var tiny: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, server.handlePdu(&.{ 0x03, 0x00, 0x64, 0x00, 0x01 }, &tiny));
}

test "hostile: a maximal read still fits max_pdu_len" {
    var regs = [_]u16{0xFFFF} ** 125;
    var server = Server.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &regs } },
    );
    var out: [mb.tcp.max_adu_len]u8 = undefined;
    var adu_buf: [mb.tcp.max_adu_len]u8 = undefined;
    const adu = try mb.tcp.encodeAdu(&adu_buf, 1, 1, &.{ 0x03, 0x00, 0x00, 0x00, 0x7D });
    const reply = (try server.handleAdu(adu, &out)).?;
    try testing.expectEqual(@as(usize, mb.tcp.header_len + 2 + 250), reply.len);
    try testing.expect(reply.len <= mb.tcp.max_adu_len);
}

// ── ADU layer: framing, unit ids, broadcast ────────────────────────────────

test "RTU: a bad CRC is silently dropped, never answered with an exception" {
    var fix = Fixture{};
    var server = fix.server(.rtu);
    var adu_buf: [mb.rtu.max_adu_len]u8 = undefined;
    var out: [mb.rtu.max_adu_len]u8 = undefined;

    const good = try mb.rtu.encodeAdu(&adu_buf, 5, &.{ 0x03, 0x00, 0x64, 0x00, 0x01 });
    try testing.expect((try server.handleAdu(good, &out)) != null);

    var corrupt: [8]u8 = undefined;
    @memcpy(&corrupt, good[0..8]);
    corrupt[7] ^= 0x01; // flip a CRC bit
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(&corrupt, &out));
    try testing.expectEqual(@as(u16, 1), server.counters.bus_comm_error);

    @memcpy(&corrupt, good[0..8]);
    corrupt[3] ^= 0x40; // flip a payload bit -> CRC no longer matches
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(&corrupt, &out));
    try testing.expectEqual(@as(u16, 2), server.counters.bus_comm_error);

    // A truncated frame is dropped too.
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(good[0..3], &out));
}

test "RTU: a broadcast applies the write but is never answered" {
    var fix = Fixture{};
    var server = fix.server(.rtu);
    var adu_buf: [mb.rtu.max_adu_len]u8 = undefined;
    var out: [mb.rtu.max_adu_len]u8 = undefined;

    const write = try mb.rtu.encodeAdu(&adu_buf, 0, &.{ 0x06, 0x00, 0x64, 0x12, 0x34 });
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(write, &out));
    try testing.expectEqual(@as(u16, 0x1234), fix.holdings[0]); // the write happened
    try testing.expectEqual(@as(u16, 1), server.counters.slave_no_response);

    // A broadcast coil write, likewise.
    const coils = try mb.rtu.encodeAdu(&adu_buf, 0, &.{ 0x0F, 0x00, 0x00, 0x00, 0x04, 0x01, 0x0B });
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(coils, &out));
    try testing.expectEqualSlices(bool, &.{ true, true, false, true }, fix.coils[0..4]);

    // A broadcast *read* is meaningless but must not answer either.
    const read = try mb.rtu.encodeAdu(&adu_buf, 0, &.{ 0x03, 0x00, 0x64, 0x00, 0x01 });
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(read, &out));
}

test "RTU: a frame for another slave is ignored entirely" {
    var fix = Fixture{};
    var server = fix.server(.rtu);
    var adu_buf: [mb.rtu.max_adu_len]u8 = undefined;
    var out: [mb.rtu.max_adu_len]u8 = undefined;

    const other = try mb.rtu.encodeAdu(&adu_buf, 6, &.{ 0x06, 0x00, 0x64, 0x12, 0x34 });
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(other, &out));
    try testing.expectEqual(@as(u16, 0), fix.holdings[0]); // nothing written
    // Seen on the bus, but not addressed to us.
    try testing.expectEqual(@as(u16, 1), server.counters.bus_message);
    try testing.expectEqual(@as(u16, 0), server.counters.slave_message);
}

test "TCP: unit 0 and 255 address the directly-connected device; RTU treats 0 as broadcast" {
    var fix = Fixture{};
    var adu_buf: [mb.tcp.max_adu_len]u8 = undefined;
    var out: [mb.tcp.max_adu_len]u8 = undefined;
    const req = [_]u8{ 0x03, 0x00, 0x64, 0x00, 0x01 };

    var tcp_server = fix.server(.tcp);
    for ([_]u8{ 5, 0, 0xFF }) |unit| {
        const adu = try mb.tcp.encodeAdu(&adu_buf, 0x1234, unit, &req);
        const reply = (try tcp_server.handleAdu(adu, &out)) orelse return error.TestUnexpectedResult;
        // The MBAP header is echoed exactly, unit id included.
        try testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x00, 0x00 }, reply[0..4]);
        try testing.expectEqual(unit, reply[6]);
    }
    // Some other unit is not ours.
    const foreign = try mb.tcp.encodeAdu(&adu_buf, 1, 6, &req);
    try testing.expectEqual(@as(?[]u8, null), try tcp_server.handleAdu(foreign, &out));

    // Opting out of the conventions.
    var strict = Server.init(.{
        .unit_id = 5,
        .framing = .tcp,
        .tcp_accept_unit_0 = false,
        .tcp_accept_unit_255 = false,
    }, .{ .holding_registers = .{ .base = 100, .values = &fix.holdings } });
    for ([_]u8{ 0, 0xFF }) |unit| {
        const adu = try mb.tcp.encodeAdu(&adu_buf, 1, unit, &req);
        try testing.expectEqual(@as(?[]u8, null), try strict.handleAdu(adu, &out));
    }

    // Gateway mode answers for anything.
    var any = Server.init(
        .{ .unit_id = 5, .framing = .tcp, .accept_any_unit = true },
        .{ .holding_registers = .{ .base = 100, .values = &fix.holdings } },
    );
    const adu = try mb.tcp.encodeAdu(&adu_buf, 1, 99, &req);
    try testing.expect((try any.handleAdu(adu, &out)) != null);
}

test "TCP: a malformed MBAP header is dropped, not answered" {
    var fix = Fixture{};
    var server = fix.server(.tcp);
    var out: [mb.tcp.max_adu_len]u8 = undefined;

    // Length field disagrees with the frame length.
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(
        &.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x99, 0x05, 0x03, 0x00, 0x64, 0x00, 0x01 },
        &out,
    ));
    // Nonzero protocol id.
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(
        &.{ 0x00, 0x01, 0x00, 0x07, 0x00, 0x06, 0x05, 0x03, 0x00, 0x64, 0x00, 0x01 },
        &out,
    ));
    // Header with no PDU behind it.
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(
        &.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05 },
        &out,
    ));
    // Truncated header.
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(&.{ 0x00, 0x01 }, &out));
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(&.{}, &out));
    // Nothing above was ever addressed to us.
    try testing.expectEqual(@as(u16, 0), server.counters.slave_message);
}

test "TCP: the transaction id is echoed, never invented" {
    var fix = Fixture{};
    var server = fix.server(.tcp);
    var adu_buf: [mb.tcp.max_adu_len]u8 = undefined;
    var out: [mb.tcp.max_adu_len]u8 = undefined;

    for ([_]u16{ 0x0000, 0x0001, 0x7FFF, 0xFFFF, 0xABCD }) |txid| {
        const adu = try mb.tcp.encodeAdu(&adu_buf, txid, 5, &.{ 0x03, 0x00, 0x64, 0x00, 0x01 });
        const reply = (try server.handleAdu(adu, &out)).?;
        try testing.expectEqual(txid, std.mem.readInt(u16, reply[0..2], .big));
        // ...and the length field matches what actually follows.
        try testing.expectEqual(
            @as(u16, @intCast(reply.len - 6)),
            std.mem.readInt(u16, reply[4..6], .big),
        );
    }
}

// ── FC 07 / 08 / 11 ─────────────────────────────────────────────────────────

test "FC 07: exception status, and IllegalFunction when not configured" {
    var out: [mb.max_pdu_len]u8 = undefined;
    var off = Server.init(.{ .unit_id = 1, .framing = .rtu }, .{});
    try expectException(try off.handlePdu(&.{0x07}, &out), 0x07, .illegal_function);

    var on = Server.init(.{ .unit_id = 1, .framing = .rtu, .exception_status = 0x6D }, .{});
    try testing.expectEqualSlices(u8, &.{ 0x07, 0x6D }, try on.handlePdu(&.{0x07}, &out));
}

test "FC 08: sub-function 0 echoes, counters report, unknown sub-functions are IllegalFunction" {
    var fix = Fixture{};
    var server = fix.server(.rtu);
    var out: [mb.max_pdu_len]u8 = undefined;

    // 0x0000 Return Query Data: echo whatever came in, however long.
    try testing.expectEqualSlices(
        u8,
        &.{ 0x08, 0x00, 0x00, 0xA5, 0x37 },
        try server.handlePdu(&.{ 0x08, 0x00, 0x00, 0xA5, 0x37 }, &out),
    );
    try testing.expectEqualSlices(
        u8,
        &.{ 0x08, 0x00, 0x00 },
        try server.handlePdu(&.{ 0x08, 0x00, 0x00 }, &out),
    );

    // Counters.
    server.counters = .{ .bus_message = 7, .bus_comm_error = 2, .slave_exception_error = 3, .slave_message = 5, .slave_no_response = 1 };
    const cases = [_]struct { sub: u8, want: u16 }{
        .{ .sub = 0x0B, .want = 7 },
        .{ .sub = 0x0C, .want = 2 },
        .{ .sub = 0x0D, .want = 3 },
        .{ .sub = 0x0E, .want = 5 },
        .{ .sub = 0x0F, .want = 1 },
    };
    for (cases) |c| {
        const reply = try server.handlePdu(&.{ 0x08, 0x00, c.sub, 0x00, 0x00 }, &out);
        try testing.expectEqual(@as(usize, 5), reply.len);
        try testing.expectEqual(c.sub, reply[2]);
        try testing.expectEqual(c.want, std.mem.readInt(u16, reply[3..5], .big));
    }

    // 0x000A Clear Counters.
    _ = try server.handlePdu(&.{ 0x08, 0x00, 0x0A, 0x00, 0x00 }, &out);
    try testing.expectEqual(@as(u16, 0), server.counters.bus_message);

    // A sub-function we do not implement.
    try expectException(
        try server.handlePdu(&.{ 0x08, 0x00, 0x20, 0x00, 0x00 }, &out),
        0x08,
        .illegal_function,
    );
    // A counter request with a nonzero data field is malformed.
    try expectException(
        try server.handlePdu(&.{ 0x08, 0x00, 0x0B, 0x00, 0x01 }, &out),
        0x08,
        .illegal_data_value,
    );
    // A truncated diagnostics PDU.
    try expectException(try server.handlePdu(&.{ 0x08, 0x00 }, &out), 0x08, .illegal_data_value);

    // Diagnostics can be turned off entirely.
    var no_diag = Server.init(.{ .unit_id = 1, .framing = .rtu, .diagnostics = false }, .{});
    try expectException(
        try no_diag.handlePdu(&.{ 0x08, 0x00, 0x00 }, &out),
        0x08,
        .illegal_function,
    );
}

test "FC 08 sub 0x0004: listen-only mode swallows everything until a restart" {
    var fix = Fixture{};
    var server = fix.server(.rtu);
    var adu_buf: [mb.rtu.max_adu_len]u8 = undefined;
    var out: [mb.rtu.max_adu_len]u8 = undefined;

    const read = try mb.rtu.encodeAdu(&adu_buf, 5, &.{ 0x03, 0x00, 0x64, 0x00, 0x01 });
    try testing.expect((try server.handleAdu(read, &out)) != null);

    var listen_buf: [mb.rtu.max_adu_len]u8 = undefined;
    const listen = try mb.rtu.encodeAdu(&listen_buf, 5, &.{ 0x08, 0x00, 0x04, 0x00, 0x00 });
    // §6.8 sub 4: no response is returned for the request that enters the mode.
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(listen, &out));
    try testing.expect(server.listen_only);

    // Now nothing is answered.
    const read2 = try mb.rtu.encodeAdu(&adu_buf, 5, &.{ 0x03, 0x00, 0x64, 0x00, 0x01 });
    try testing.expectEqual(@as(?[]u8, null), try server.handleAdu(read2, &out));

    // ...except the restart sub-function.
    var restart_buf: [mb.rtu.max_adu_len]u8 = undefined;
    const restart = try mb.rtu.encodeAdu(&restart_buf, 5, &.{ 0x08, 0x00, 0x01, 0x00, 0x00 });
    try testing.expect((try server.handleAdu(restart, &out)) != null);
    try testing.expect(!server.listen_only);

    const read3 = try mb.rtu.encodeAdu(&adu_buf, 5, &.{ 0x03, 0x00, 0x64, 0x00, 0x01 });
    try testing.expect((try server.handleAdu(read3, &out)) != null);
}

test "FC 11: report slave id, and IllegalFunction when no id is configured" {
    var out: [mb.max_pdu_len]u8 = undefined;
    var off = Server.init(.{ .unit_id = 1, .framing = .rtu }, .{});
    try expectException(try off.handlePdu(&.{0x11}, &out), 0x11, .illegal_function);

    var on = Server.init(.{
        .unit_id = 1,
        .framing = .rtu,
        .slave_id = "AB",
        .slave_id_extra = &.{0x77},
        .run_indicator = false,
    }, .{});
    try testing.expectEqualSlices(
        u8,
        &.{ 0x11, 0x04, 'A', 'B', 0x00, 0x77 },
        try on.handlePdu(&.{0x11}, &out),
    );
}

// ── write hook ──────────────────────────────────────────────────────────────

test "write hook fires once per write, after the data bank is already updated" {
    const Recorder = struct {
        events: [8]WriteEvent = undefined,
        n: usize = 0,
        bank: *[16]u16 = undefined,
        saw_value: u16 = 0,

        fn hook(self: *@This()) WriteHook {
            return .{ .ctx = self, .onWriteFn = onWrite };
        }

        fn onWrite(ctx: *anyopaque, event: WriteEvent) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.n < self.events.len) self.events[self.n] = event;
            self.n += 1;
            if (event.area == .holding_registers) self.saw_value = self.bank[0];
        }
    };

    var fix = Fixture{};
    var server = fix.server(.rtu);
    var rec = Recorder{ .bank = &fix.holdings };
    server.setWriteHook(rec.hook());
    var out: [mb.max_pdu_len]u8 = undefined;

    _ = try server.handlePdu(&.{ 0x06, 0x00, 0x64, 0xAB, 0xCD }, &out);
    _ = try server.handlePdu(&.{ 0x05, 0x00, 0x02, 0xFF, 0x00 }, &out);
    _ = try server.handlePdu(&.{ 0x10, 0x00, 0x65, 0x00, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02 }, &out);
    _ = try server.handlePdu(&.{ 0x0F, 0x00, 0x00, 0x00, 0x03, 0x01, 0x05 }, &out);
    // A rejected write must not fire the hook.
    _ = try server.handlePdu(&.{ 0x06, 0xFF, 0xFF, 0x00, 0x01 }, &out);
    // Reads never fire it.
    _ = try server.handlePdu(&.{ 0x03, 0x00, 0x64, 0x00, 0x01 }, &out);

    try testing.expectEqual(@as(usize, 4), rec.n);
    try testing.expectEqual(Area.holding_registers, rec.events[0].area);
    try testing.expectEqual(@as(u16, 100), rec.events[0].addr);
    try testing.expectEqual(@as(u16, 1), rec.events[0].count);
    try testing.expectEqual(Area.coils, rec.events[1].area);
    try testing.expectEqual(@as(u16, 2), rec.events[1].addr);
    try testing.expectEqual(@as(u16, 101), rec.events[2].addr);
    try testing.expectEqual(@as(u16, 2), rec.events[2].count);
    try testing.expectEqual(Area.coils, rec.events[3].area);
    try testing.expectEqual(@as(u16, 3), rec.events[3].count);
    // The hook observed the *new* value, so it ran after the write landed.
    try testing.expectEqual(@as(u16, 0xABCD), rec.saw_value);
}

// ── fuzz ────────────────────────────────────────────────────────────────────

test "fuzz: random PDUs and ADUs never panic and always resolve to a reply or silence" {
    var coils = [_]bool{false} ** 64;
    var discretes = [_]bool{false} ** 64;
    var holdings = [_]u16{0} ** 64;
    var inputs = [_]u16{0} ** 64;
    var server = Server.init(.{
        .unit_id = 5,
        .framing = .tcp,
        .exception_status = 0x11,
        .slave_id = "fuzz",
    }, .{
        .coils = .{ .base = 0, .values = &coils },
        .discrete_inputs = .{ .base = 10, .values = &discretes },
        .holding_registers = .{ .base = 100, .values = &holdings },
        .input_registers = .{ .base = 1000, .values = &inputs },
    });

    var state: u32 = 0x1D872B41;
    var frame: [400]u8 = undefined;
    var out: [mb.tcp.max_adu_len]u8 = undefined;
    var pdu_out: [mb.max_pdu_len]u8 = undefined;

    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
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

        // handlePdu always answers something well-formed.
        const reply = server.handlePdu(bytes, &pdu_out) catch |err| {
            try testing.expectEqual(error.BufferTooSmall, err);
            continue;
        };
        try testing.expect(reply.len >= 2 and reply.len <= mb.max_pdu_len);
        if (len > 0 and reply[0] == (bytes[0] | 0x80) and reply.len == 2) {
            // An exception response: the code must be one we can name.
            try testing.expect(switch (reply[1]) {
                0x01, 0x02, 0x03, 0x04 => true,
                else => false,
            });
        }

        // handleAdu either answers a decodable frame or stays silent.
        server.config.framing = if (state & 1 == 0) .tcp else .rtu;
        if (try server.handleAdu(bytes, &out)) |adu| {
            switch (server.config.framing) {
                .tcp => _ = try mb.tcp.decodeAdu(adu),
                .rtu => _ = try mb.rtu.decodeAdu(adu),
            }
        }
    }
}

test "fuzz: structurally valid requests with wire-controlled fields never panic" {
    // Same as above but every PDU starts with a real function code, so the
    // fuzzer spends its budget inside the handlers rather than bouncing off
    // the dispatch table.
    var coils = [_]bool{false} ** 64;
    var holdings = [_]u16{0} ** 64;
    var server = Server.init(.{ .unit_id = 1, .framing = .rtu }, .{
        .coils = .{ .base = 7, .values = &coils },
        .holding_registers = .{ .base = 0xFFF0, .values = &holdings },
    });

    const fcs = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0F, 0x10, 0x11, 0x17 };
    var state: u32 = 0x9E3779B9;
    var frame: [300]u8 = undefined;
    var out: [mb.max_pdu_len]u8 = undefined;

    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        const len = 1 + state % 40;
        frame[0] = fcs[state % fcs.len];
        for (frame[1..len]) |*b| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            b.* = @truncate(state);
        }
        const reply = try server.handlePdu(frame[0..len], &out);
        try testing.expect(reply.len >= 2);
        // Either an echo of the function code, or that code with the high bit.
        try testing.expect(reply[0] == frame[0] or reply[0] == frame[0] | 0x80);
    }
}

// The two loops above are fixed-seed: they are reproducible, but `zig build
// --fuzz` (and therefore `scripts/fuzz-sweep.sh`) only drives
// `std.testing.fuzz` entry points, so without the harness below the whole
// server — the only part of this module that an unauthenticated peer can
// reach and that writes to a process image — would never be explored by the
// coverage-guided sweep.

test "fuzz: the server never panics and always answers or stays silent" {
    try testing.fuzz({}, fuzzServer, .{});
}

fn fuzzServer(_: void, smith: *std.testing.Smith) !void {
    var coils = [_]bool{false} ** 64;
    var discretes = [_]bool{false} ** 64;
    var holdings = [_]u16{0} ** 64;
    var inputs = [_]u16{0} ** 64;
    var server = Server.init(.{
        .unit_id = 5,
        .framing = if (smith.value(bool)) .tcp else .rtu,
        .exception_status = 0x11,
        .slave_id = "fuzz",
    }, .{
        .coils = .{ .base = 0, .values = &coils },
        .discrete_inputs = .{ .base = 10, .values = &discretes },
        // Deliberately butted against the top of the 16-bit address space so
        // that any `addr + quantity` computed in a narrow type wraps here.
        .holding_registers = .{ .base = 0xFFC0, .values = &holdings },
        .input_registers = .{ .base = 1000, .values = &inputs },
    });

    var frame: [300]u8 = undefined;
    smith.bytes(&frame);
    const len: usize = smith.valueRangeAtMost(u16, 0, frame.len);
    const bytes = frame[0..len];

    // Half the budget goes to PDUs that start with a real function code, so
    // the fuzzer spends its time inside the handlers rather than bouncing off
    // the dispatch table.
    if (len > 0 and smith.value(bool)) {
        const fcs = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0F, 0x10, 0x11, 0x17 };
        frame[0] = fcs[smith.index(fcs.len)];
    }

    var pdu_out: [mb.max_pdu_len]u8 = undefined;
    const reply = try server.handlePdu(bytes, &pdu_out);
    try testing.expect(reply.len >= 2 and reply.len <= mb.max_pdu_len);
    if (len > 0) {
        try testing.expect(reply[0] == bytes[0] or reply[0] == bytes[0] | 0x80);
    }

    var out: [mb.tcp.max_adu_len]u8 = undefined;
    if (try server.handleAdu(bytes, &out)) |adu| {
        // Whatever we put on the wire must be a frame we can decode again.
        switch (server.config.framing) {
            .tcp => _ = try mb.tcp.decodeAdu(adu),
            .rtu => _ = try mb.rtu.decodeAdu(adu),
        }
    }
}
